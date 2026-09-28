/* Presentation of supplied detector evidence; no threat classification. */
window.DrashtaThreats = (() => {
  const metric=(label,keys,unit='',kind='number')=>({label,keys,unit,kind});
  const categories=[
    {id:'ddos',label:'DDoS',classes:['SYN_FLOOD','UDP_REFLECT'],color:'#d84260',metrics:[
      metric('Packets / second',['packets_per_second','packet_rate'],'packets/s'),metric('Bytes / second',['bytes_per_second','byte_rate'],'bytes/s'),
      metric('SYN rate',['syn_rate','syn_per_second'],'SYN/s'),metric('UDP rate',['udp_rate','udp_packets_per_second'],'packets/s'),
      metric('Source-IP entropy',['source_ip_entropy','src_ip_entropy'],'bits'),metric('Destination concentration',['destination_concentration','dst_concentration']),metric('Traffic burst',['traffic_burst','burst_ratio']),metric('Mean inter-arrival time',['iat_mean_seconds','mean_iat_seconds'],'s')]},
    {id:'beacon',label:'C2 Beaconing',classes:['C2_BEACON'],color:'#7953cc',metrics:[
      metric('Inter-arrival time',['iat_mean_seconds','beacon_iat_mean_seconds'],'s'),metric('IAT variance',['iat_variance_seconds2','beacon_iat_variance'],'s²'),
      metric('Periodicity',['beacon_period_seconds','period_seconds'],'s'),metric('Destination frequency',['destination_frequency','destination_counts'],'','distribution'),
      metric('Packet-size consistency',['packet_size_cv','packet_size_consistency'])]},
    {id:'dns',label:'DNS / DGA',classes:['DNS_DGA','DNS_DNSCAT2'],color:'#1199b7',metrics:[
      metric('Domain entropy',['dns_query_entropy','domain_entropy'],'bits'),metric('Domain length',['query_length','domain_length'],'characters'),
      metric('Character distribution',['character_distribution','domain_character_counts'],'','distribution'),metric('N-gram anomaly',['ngram_anomaly','ngram_anomaly_score']),
      metric('Query rate',['dns_queries_per_second','query_rate'],'queries/s'),metric('Record type distribution',['dns_record_type_counts','record_type_distribution'],'','distribution')]},
    {id:'encrypted',label:'Encrypted Malware',classes:['TLS_C2'],color:'#2578b9',metrics:[
      metric('JA3 / JA3S / JA4',['ja3','ja3s','ja4'],'','fingerprints'),metric('Packet-size pattern',['packet_size_sequence','packet_sizes'],'bytes','sequence'),
      metric('Timing sequence',['timing_sequence_seconds','iat_sequence_seconds'],'s','sequence'),metric('Session duration',['duration_seconds','session_duration_seconds'],'s'),
      metric('TLS / QUIC metadata anomalies',['tls_metadata_anomalies','quic_metadata_anomalies','metadata_anomalies'],'','text')]},
    {id:'recon',label:'Recon / Scanning',classes:['PORT_SCAN'],color:'#b456ba',metrics:[
      metric('Destination ports',['unique_dst_ports'],'ports'),metric('Destination hosts',['unique_dst_hosts'],'hosts'),metric('Scan rate',['scan_rate','connections_per_second'],'flows/s'),
      metric('Source fan-out',['source_fanout','fanout_count']),metric('Session duration',['duration_seconds'],'s')]},
    {id:'exfil',label:'Exfiltration',classes:['EXFIL'],color:'#d77e2e',metrics:[
      metric('Outbound / inbound byte ratio',['outbound_inbound_byte_ratio','outbound_to_inbound_ratio']),metric('Outbound bytes',['outbound_bytes','src_bytes'],'bytes'),
      metric('Inbound bytes',['inbound_bytes','dst_bytes'],'bytes'),metric('Bytes / second',['bytes_per_second'],'bytes/s'),metric('Session duration',['duration_seconds'],'s')]}
  ];
  function values(records,definition){
    const result=[];
    for(const row of records){
      const evidence=row.evidence||{};
      if(definition.kind==='fingerprints'){
        for(const key of definition.keys)if(typeof evidence[key]==='string'&&evidence[key].trim())result.push({row,key,value:key.toUpperCase()+': '+evidence[key]});
        continue;
      }
      for(const key of definition.keys){
        const value=evidence[key];
        const valid=definition.kind==='number'?typeof value==='number'&&Number.isFinite(value):
          definition.kind==='sequence'?Array.isArray(value)&&value.length>0&&value.every(n=>typeof n==='number'&&Number.isFinite(n)):
          definition.kind==='distribution'?value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length>0&&Object.values(value).every(n=>typeof n==='number'&&Number.isFinite(n)&&n>=0):
          typeof value==='string'&&value.trim()||Array.isArray(value)&&value.length>0&&value.every(n=>typeof n==='string');
        if(valid){result.push({row,key,value});break;}
      }
    }
    return result;
  }
  return {categories,values};
})();
