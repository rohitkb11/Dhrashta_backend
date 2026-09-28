/* Fictional browser-only preview. Never posts observations, alerts or reports. */
window.DrashtaPreview = (() => {
  const now=Date.now(),classes=['C2_BEACON','SYN_FLOOD','BENIGN','PORT_SCAN','UDP_REFLECT','DNS_DGA','TLS_C2','EXFIL','DNS_DNSCAT2'];
  const sources=['192.0.2.12','192.0.2.24','192.0.2.36','192.0.2.48','192.0.2.60','192.0.2.72'];
  const destinations=['198.51.100.10','198.51.100.20','198.51.100.30','203.0.113.40'];
  const band=confidence=>confidence>=.85?'high':confidence>=.7?'medium':'low';
  const stamp=value=>new Date(value).toISOString();
  const alerts=Array.from({length:240},(_,index)=>{
    const cls=classes[(index*7+Math.floor(index/11))%classes.length],confidence=cls==='BENIGN' ? .55+(index%30)/100 : [.96,.91,.87,.82,.77,.72,.66,.61][index%8];
    const age=index<100 ? ((index*index*7+index*79)%86400)*1000 : (1+(index%6))*86400000+(index%23)*3600000;
    const input=index%3,src=sources[index%6],dst=destinations[(Math.floor(index/6)+input)%4];
    const evidence={sample_preview:true,packet_count:120+(index*137)%28000,byte_count:9600+(index*42137)%8200000,duration_seconds:2+(index*17)%180,src_ip:src,dst_ip:dst};
    if(cls==='C2_BEACON'){evidence.beacon_iat_cv=.008+(index%8)*.003;evidence.beacon_period_seconds=30+(index%3)*30;}
    if(cls==='SYN_FLOOD'){evidence.syn_count=2600+index*91;evidence.packets_per_second=850+(index*31)%9500;}
    if(cls.startsWith('DNS')){evidence.dns_query_entropy=3.4+(index%15)/10;evidence.query_length=46+(index*7)%120;evidence.dns_query='sample-'+index+'.example';}
    if(cls==='TLS_C2')evidence.tls_fingerprint='sample-metadata-fingerprint-'+index%4;
    if(cls==='PORT_SCAN'){evidence.unique_dst_ports=24+(index*11)%700;evidence.unique_dst_hosts=8+index%32;}
    if(cls==='EXFIL')evidence.outbound_inbound_byte_ratio=18+(index*7)%90;
    if(cls==='UDP_REFLECT')evidence.response_request_byte_ratio=12+(index%35);
    evidence.bytes_per_second=evidence.byte_count/evidence.duration_seconds;
    if(!Number.isFinite(evidence.packets_per_second))evidence.packets_per_second=evidence.packet_count/evidence.duration_seconds;
    if(cls==='SYN_FLOOD'||cls==='UDP_REFLECT')Object.assign(evidence,{syn_rate:cls==='SYN_FLOOD'?1200+index*9:0,udp_rate:cls==='UDP_REFLECT'?3200+index*13:0,source_ip_entropy:2.1+index%12/5,destination_concentration:.7+index%20/100,traffic_burst:3+index%14});
    if(cls==='SYN_FLOOD'||cls==='UDP_REFLECT'){evidence.packets_per_second=Math.max(evidence.packets_per_second,evidence.syn_rate+evidence.udp_rate);evidence.iat_mean_seconds=1/evidence.packets_per_second;evidence.packet_count=Math.round(evidence.packets_per_second*evidence.duration_seconds);evidence.byte_count=evidence.packet_count*(cls==='UDP_REFLECT'?1200:64);evidence.bytes_per_second=evidence.byte_count/evidence.duration_seconds;}
    if(cls==='C2_BEACON')Object.assign(evidence,{iat_mean_seconds:30+index%3*30,iat_variance_seconds2:.02+index%8/100,destination_frequency:{'198.51.100.10':12+index%16,'198.51.100.20':3+index%5},packet_size_cv:.01+index%5/100});
    if(cls.startsWith('DNS'))Object.assign(evidence,{character_distribution:{letters:32+index%12,digits:18+index%8,separators:3},ngram_anomaly_score:.71+index%20/100,dns_queries_per_second:12+index%23,dns_record_type_counts:{TXT:22+index%12,A:4+index%5,AAAA:2}});
    if(cls==='TLS_C2')Object.assign(evidence,{ja4:'sample-ja4-'+index%4,ja3:'sample-ja3-'+index%3,packet_size_sequence:[64,1480,96,1280,64],timing_sequence_seconds:[0,.05,.3,.02,1.2],tls_metadata_anomalies:['Illustrative repeated fingerprint','Illustrative timing pattern']});
    if(cls==='PORT_SCAN')Object.assign(evidence,{scan_rate:15+index%60,source_fanout:10+index%40});
    if(cls==='EXFIL')Object.assign(evidence,{outbound_bytes:evidence.byte_count,inbound_bytes:Math.floor(evidence.byte_count/evidence.outbound_inbound_byte_ratio)});
    const sampleReasons={
      C2_BEACON:`Illustrative beaconing label: repeated sample observations have a ${evidence.beacon_period_seconds}s period and an inter-arrival coefficient of variation of ${evidence.beacon_iat_cv}.`,
      SYN_FLOOD:`Illustrative SYN-flood label: the sample contains ${evidence.syn_count} SYN packets and a SYN rate of ${evidence.syn_rate}/s toward concentrated destinations.`,
      UDP_REFLECT:`Illustrative reflection label: the sample response/request byte ratio is ${evidence.response_request_byte_ratio}, with a UDP rate of ${evidence.udp_rate} packets/s.`,
      DNS_DGA:`Illustrative DGA label: sample query entropy is ${evidence.dns_query_entropy} bits, query length is ${evidence.query_length}, and n-gram anomaly score is ${evidence.ngram_anomaly_score}.`,
      DNS_DNSCAT2:`Illustrative DNS-tunnelling label: the sample combines long queries (${evidence.query_length} characters), query entropy (${evidence.dns_query_entropy} bits) and a TXT-heavy record distribution.`,
      TLS_C2:'Illustrative encrypted-session label: the sample includes a repeated fingerprint, packet-size sequence and timing pattern. No encrypted payload was decrypted.',
      PORT_SCAN:`Illustrative scanning label: the sample source reaches ${evidence.unique_dst_ports} ports across ${evidence.unique_dst_hosts} destination hosts.`,
      EXFIL:`Illustrative exfiltration label: sample outbound/inbound byte ratio is ${evidence.outbound_inbound_byte_ratio}, supported by directional byte counts.`
    };
    if(sampleReasons[cls])evidence.reason=sampleReasons[cls]+' Fictional evidence; no model inference occurred.';
    evidence.protocol=cls.startsWith('DNS')||cls==='UDP_REFLECT'?17:6;
    if(cls!=='BENIGN'){
      evidence.anomaly_score=Number((.7+index%25/100).toFixed(2));
      evidence.feature_assessments=Object.fromEntries(Object.entries(evidence).filter(([key,value])=>typeof value==='number'&&!['protocol','anomaly_score'].includes(key)).map(([key])=>[key,{level:'Sample indicator'}]));
      evidence.contributions=[sampleReasons[cls]];
      evidence.flow_timeline=[{timestamp:stamp(now-age-12000),event:'Sample baseline observation'},{timestamp:stamp(now-age-7000),event:'Sample traffic pattern changed'},{timestamp:stamp(now-age-2000),event:'Sample unusual pattern'},{timestamp:stamp(now-age),event:'Illustrative alert recorded'}];
    }
    return {id:'sample-alert-'+String(index+1).padStart(4,'0'),timestamp:stamp(now-age),received_at:stamp(now-index%59*1000),flow_id:'sample-flow-'+String(index+1).padStart(4,'0'),input_id:'sample-input-'+(input+1),threat_class:cls,confidence,severity:band(confidence),evidence,model_version:'Illustrative labels · no detection model',origin:input===0?'live':'upload',src_ip:src,dst_ip:dst,endpoint_source:{src:'sample observation',dst:'sample observation'},visibility:{observed_direction:index%4===0?'forward':'both',reverse_available:index%4!==0,partial_flow:index%7===0,capture_loss:index%9===0?.018:0}};
  }).sort((a,b)=>b.timestamp.localeCompare(a.timestamp)||b.id.localeCompare(a.id));
  const observations=alerts.map(alert=>({flow_id:alert.flow_id,timestamp:alert.timestamp,src_ip:alert.src_ip,dst_ip:alert.dst_ip,src_port:41000+Number(alert.id.slice(-4)),dst_port:alert.threat_class.startsWith('DNS')?53:alert.threat_class==='TLS_C2'?443:80,protocol:alert.threat_class.startsWith('DNS')||alert.threat_class==='UDP_REFLECT'?17:6,features:alert.evidence,feature_version:'sample-preview',source_timestamp_supplied:true}));
  const inputs=Array.from({length:3},(_,index)=>{
    const records=observations.filter(row=>alerts.find(alert=>alert.flow_id===row.flow_id).input_id==='sample-input-'+(index+1));
    const original=JSON.stringify({sample_preview:true,records},null,2);
    return {id:'sample-input-'+(index+1),format:'metadata',origin:index===0?'live':'upload',created_at:stamp(now-(index+1)*3600000),flow_count:records.length,alert_count:records.length,bytes:new TextEncoder().encode(original).length,state:'sample_preview',processing_ms:null,sha256:null,notes:['Fictional preview observations; not collected traffic.'],records,original};
  });
  const counts=data=>data.reduce((result,row)=>(result[row.threat_class]=(result[row.threat_class]||0)+1,result),{});
  const summary={total:alerts.length,high_severity:alerts.filter(row=>row.confidence>=.85).length,distinct_classes:classes.length,by_class:counts(alerts),source:'sample preview'};
  const sourcesForReport=alerts.filter(row=>row.threat_class!=='BENIGN').slice(0,3).map((alert,index)=>({ref:'A'+(index+1),alert}));
  const report={id:'sample-report-0001',title:'Sample investigation · passive traffic review',created_at:stamp(now-1800000),completed_at:stamp(now-1750000),state:'draft',provider:'Sample preview',model:'No LLM called · illustrative narrative',source_count:3,sources:sourcesForReport,source_sha256:null,error:null,usage:null,narrative:{summary:'This fictional report illustrates how saved alerts and their evidence can be reviewed together. It describes the sample labels; it is not a validated incident or an LLM-generated report.',findings:sourcesForReport.map(source=>({title:source.alert.threat_class+' · example evidence',analysis:'The sample record links '+source.alert.src_ip+' to '+source.alert.dst_ip+' with a confidence score of '+Math.round(source.alert.confidence*100)+'%. Its evidence fields demonstrate what an analyst would inspect; these values were not measured on a live network.',alert_refs:[source.ref]})),recommendations:['Review the original observation and its visibility before accepting a detector label.','Correlate repeat observations using flow IDs and detection times.'],limitations:['Fictional sample records only. No live capture, detection inference or Gemini request occurred.','Confidence bands show detector scores, not verified impact.']}};
  function canonical(value){if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';return JSON.stringify(value);}
  const hashes=Promise.all(inputs.map(async input=>{input.sha256=await digest(input.original);})).then(async()=>{report.source_sha256=await digest(canonical(sourcesForReport));});
  async function digest(text){if(!crypto.subtle)return null;const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));return [...new Uint8Array(bytes)].map(value=>value.toString(16).padStart(2,'0')).join('');}
  function filtered(params){
    const id=params.get('alert_id')?.trim(),ip=params.get('ip'),since=params.get('since'),until=params.get('until');
    if((since&&!Number.isFinite(Date.parse(since)))||(until&&!Number.isFinite(Date.parse(until))))throw Error('Use a valid date and time.');
    if(since&&until&&Date.parse(since)>=Date.parse(until))throw Error('End time must follow start time.');
    return alerts.filter(row=>(!id||row.id===id)&&(!ip||row.src_ip===ip||row.dst_ip===ip)&&(!params.get('threat_class')||row.threat_class===params.get('threat_class'))&&(!params.get('severity')||row.severity===params.get('severity'))&&(!params.get('origin')||row.origin===params.get('origin'))&&(!since||Date.parse(row.timestamp)>=Date.parse(since))&&(!until||Date.parse(row.timestamp)<Date.parse(until))&&(params.get('exclude_benign')!=='true'||row.threat_class!=='BENIGN'));
  }
  function network(params){
    const mode=params.get('mode')||'live',id=params.get('input_id'),selected=mode==='capture' ? alerts.filter(row=>row.input_id===id):alerts.filter(row=>row.origin==='live');
    const pairs=new Map();for(const alert of selected){const key=alert.src_ip+'|'+alert.dst_ip;if(!pairs.has(key))pairs.set(key,{src_ip:alert.src_ip,dst_ip:alert.dst_ip,observations:0,alerts:0,unusual_alerts:0,peak_confidence:null});const edge=pairs.get(key);edge.observations++;edge.alerts++;if(alert.threat_class!=='BENIGN'){edge.unusual_alerts++;edge.peak_confidence=Math.max(edge.peak_confidence||0,alert.confidence);}}
    const edges=[...pairs.values()].filter(edge=>params.get('unusual_only')!=='true'||edge.unusual_alerts),ips=[...new Set(edges.flatMap(edge=>[edge.src_ip,edge.dst_ip]))];
    return {mode,nodes:ips.map(ip=>({ip,unusual_alerts:edges.filter(edge=>edge.src_ip===ip||edge.dst_ip===ip).reduce((sum,edge)=>sum+edge.unusual_alerts,0)})),edges,observations:selected.length,mapped_alerts:selected.length,unmapped_alerts:0,unmapped_observations:0,omitted_edges:0,scope:'Sample '+(mode==='live'?'passive-feed window':'saved observations')};
  }
  async function read(path){
    const url=new URL(path,location.origin),p=url.pathname,q=url.searchParams;
    if(p==='/api/alerts')return {alerts:alerts.slice(0,Number(q.get('limit')||100)),source:'sample preview'};
    if(p==='/api/stats')return summary;
    if(p==='/api/ingest'){await hashes;const tick=Math.floor(Date.now()/1000),series=Array.from({length:60},(_,index)=>{const second=tick-60+index;return {timestamp:stamp(second*1000),datagrams:Math.round(420+95*Math.sin(second/7)+60*Math.sin(second/3)+(second%40<5?210:0))};}),rate=series.at(-1).datagrams;return {inputs:inputs.map(({records,original,...input})=>input),limits:{max_upload_bytes:10485760,max_flows:10000,max_packets:100000},model:{available:false,state:'awaiting_model'},monitor:{active:false,bound:false,port:2055,published_host:'Sample preview',published_port:2055,received:36000+Math.max(0,tick-Math.floor(now/1000))*420,processed:35940+Math.max(0,tick-Math.floor(now/1000))*420,rejected:12,queue_dropped:48,ignored_while_paused:0,queued:0,last_received_at:stamp(tick*1000),rate_window_seconds:60,flow_records_per_second:rate,feed_mbps:rate*400*8/1000000,rate_scope:'Illustrative passive feed rates; not measured traffic',receipt_series:series,mode:'sample_preview'}};}
    if(p==='/api/history'){const all=filtered(q),offset=Number(q.get('cursor')||0),limit=Number(q.get('limit')||50);if(!Number.isInteger(offset)||offset<0)throw Error('Invalid sample history cursor');return {alerts:all.slice(offset,offset+limit),total:all.length,next_cursor:offset+limit<all.length?String(offset+limit):null,source:'sample preview'};}
    if(p.startsWith('/api/history/')){const record=alerts.find(row=>row.id===decodeURIComponent(p.split('/').pop()));if(!record)throw Error('Sample alert not found');return record;}
    if(p==='/api/network')return network(q);
    if(p==='/api/analytics/heatmap'){
      const end=new Date(now);end.setUTCHours(0,0,0,0);const start=end.getTime()-6*86400000;
      const days=Array.from({length:7},(_,index)=>({date:stamp(start+index*86400000).slice(0,10),hours:Array.from({length:24},()=>({count:0,peak_confidence:null}))}));let total=0,benign_excluded=0;
      for(const alert of alerts){const day=days.find(day=>day.date===alert.timestamp.slice(0,10));if(!day)continue;if(alert.threat_class==='BENIGN'){benign_excluded++;continue;}const cell=day.hours[new Date(alert.timestamp).getUTCHours()];cell.count++;cell.peak_confidence=Math.max(cell.peak_confidence||0,alert.confidence);total++;}return {days,total,benign_excluded,timezone:'UTC',source:'sample preview'};
    }
    if(p==='/api/investigations/ip'){
      const ip=q.get('address'),selected=alerts.filter(row=>row.src_ip===ip||row.dst_ip===ip),peers={},bands={high:0,medium:0,low:0};for(const row of selected){bands[row.severity]++;const peer=row.src_ip===ip?row.dst_ip:row.src_ip;peers[peer]=(peers[peer]||0)+1;}
      return {ip,total_alerts:selected.length,first_detection:selected.at(-1)?.timestamp||null,last_detection:selected[0]?.timestamp||null,by_class:counts(selected),confidence_bands:bands,peers:Object.entries(peers).map(([ip,alerts])=>({ip,alerts})).sort((a,b)=>b.alerts-a.alerts),peers_total:Object.keys(peers).length,missing_peer:0,generated_at:stamp(now),source:'sample preview',scope:'Fictional sample alert evidence only. No reputation, geolocation or active network queries.'};
    }
    if(p.startsWith('/api/ingest/')){await hashes;const input=inputs.find(input=>input.id===p.split('/')[3]);if(!input)throw Error('Sample input not found');if(p.endsWith('/features'))return {input_id:input.id,feature_version:'sample-preview',records:input.records};const {records,original,...summary}=input;return summary;}
    if(p.startsWith('/api/reports')){await hashes;if(p==='/api/reports')return {reports:[report],generator:{provider:'Sample preview',configured:false,available:true,model:null}};if(p.split('/')[3]===report.id)return report;throw Error('Sample report not found');}
    throw Error('This action is not available in sample preview.');
  }
  async function download(path){
    const url=new URL(path,location.origin);await hashes;
    if(url.pathname.endsWith('/original')){const input=inputs.find(input=>input.id===url.pathname.split('/')[3]);if(!input)throw Error('Sample input not found');return {body:input.original,mime:'application/json',name:input.id+'-observations.json'};}
    const result=await read(path);if(url.pathname.includes('/reports/')&&url.searchParams.get('format')==='text')return {body:'SAMPLE PREVIEW — no LLM generation\n\n'+report.title+'\n\n'+report.narrative.summary+'\n\n'+report.narrative.findings.map(finding=>finding.title+'\n'+finding.analysis+'\nSources: '+finding.alert_refs.join(', ')).join('\n\n')+'\n\n'+JSON.stringify(report.sources,null,2),mime:'text/plain',name:'drashta-sample-report.txt'};
    return {body:JSON.stringify(result,null,2),mime:'application/json',name:'drashta-sample-evidence.json'};
  }
  return {read,download};
})();
