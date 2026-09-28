/* Browser-only fixtures must remain internally consistent without network I/O. */
const assert = require('node:assert/strict');
const { createHash, webcrypto } = require('node:crypto');
global.window = {};
global.location = { origin: 'http://localhost:8000' };
global.crypto = webcrypto;
global.fetch = () => { throw Error('Sample preview attempted a network request'); };
require('../backend/static/preview.js');
const { read, download } = window.DrashtaPreview;

(async () => {
  const all = [];
  let cursor = null;
  do {
    const page = await read('/api/history?limit=50' + (cursor ? '&cursor=' + cursor : ''));
    all.push(...page.alerts);
    cursor = page.next_cursor;
    assert.equal(page.total, 240);
  } while (cursor);
  assert.equal(new Set(all.map(row => row.id)).size, 240);
  const stats = await read('/api/stats');
  assert.equal(Object.values(stats.by_class).reduce((a, b) => a + b, 0), all.length);
  for (const row of all) {
    assert.equal(row.evidence.sample_preview, true);
    assert.equal((await read('/api/history?alert_id=' + row.id)).alerts[0].flow_id, row.flow_id);
  }
  const nonbenign = await read('/api/history?exclude_benign=true&limit=1000');
  assert.equal(nonbenign.total, all.filter(row => row.threat_class !== 'BENIGN').length);
  const heatmap = await read('/api/analytics/heatmap');
  for (const day of heatmap.days) {
    for (let hour = 0; hour < 24; hour++) {
      const since = new Date(day.date + 'T00:00:00Z');
      since.setUTCHours(hour);
      const until = new Date(+since + 3600000);
      const page = await read('/api/history?exclude_benign=true&since=' + since.toISOString() + '&until=' + until.toISOString());
      assert.equal(page.total, day.hours[hour].count);
    }
  }
  const ingest = await read('/api/ingest');
  assert.equal(ingest.monitor.active, false);
  assert.equal(ingest.monitor.bound, false);
  assert.equal(ingest.model.available, false);
  for (const input of ingest.inputs) {
    const original = await download('/api/ingest/' + input.id + '/original');
    assert.equal(createHash('sha256').update(original.body).digest('hex'), input.sha256);
    const records = JSON.parse(original.body).records;
    const graph = await read('/api/network?mode=capture&input_id=' + input.id);
    assert.equal(graph.observations, records.length);
    assert.equal(graph.edges.reduce((sum, edge) => sum + edge.alerts, 0), records.length);
  }
  const live = await read('/api/network?mode=live');
  assert.equal(live.observations, all.filter(row => row.origin === 'live').length);
  const unusual = await read('/api/network?mode=live&unusual_only=true');
  assert.ok(unusual.edges.every(edge => edge.unusual_alerts > 0));
  const ip = all[0].src_ip;
  const investigation = await read('/api/investigations/ip?address=' + ip);
  assert.equal(investigation.total_alerts, all.filter(row => row.src_ip === ip || row.dst_ip === ip).length);
  const report = (await read('/api/reports')).reports[0];
  assert.match(report.model, /No LLM called/);
  assert.equal(report.sources.length, report.source_count);
  assert.match(report.source_sha256, /^[a-f0-9]{64}$/);
  const text = await download('/api/reports/' + report.id + '/download?format=text');
  assert.match(text.body, /SAMPLE PREVIEW/);
  await assert.rejects(read('/api/unavailable'), /not available/);
  console.log('Sample preview checks passed: pagination, filters, heatmap, inputs, graphs, hashes, IP evidence and report references.');
})().catch(error => { console.error(error); process.exitCode = 1; });
