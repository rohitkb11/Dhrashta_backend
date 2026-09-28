/* Local SVG charts. Values and labels are provided by the selected dataset. */
window.DrashtaCharts = (() => {
  const palette = {BENIGN:'#18866d',C2_BEACON:'#7953cc',TLS_C2:'#4d68ce',DNS_DGA:'#1388bb',DNS_DNSCAT2:'#0a9893',EXFIL:'#d44b87',SYN_FLOOD:'#ed8650',UDP_REFLECT:'#259bcb',PORT_SCAN:'#b355bb',high:'#e24965',medium:'#e89736',low:'#278bb4',unknown:'#8b9bb1'};
  const element = (tag, text, cls) => {const node=document.createElement(tag); if(text!==undefined)node.textContent=text; if(cls)node.className=cls; return node;};
  const svg = (tag, attrs={}, text) => {const node=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [key,value] of Object.entries(attrs))node.setAttribute(key,String(value));if(text!==undefined)node.textContent=text;return node;};
  const compact = value => value.toLocaleString(undefined,{maximumSignificantDigits:4});
  function empty(container) {container.replaceChildren(element('p','No data in this selection','chart-empty'));}
  function frame(container,label,height=250) {
    const style=getComputedStyle(container),width=Math.max(240,(container.clientWidth || 480)-parseFloat(style.paddingLeft)-parseFloat(style.paddingRight)),node=svg('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':label,class:'portal-chart'});
    node.append(svg('title',{},label));return {node,width,height};
  }
  function axis(node,width,peak,bottom=200) {
    for(const value of [...new Set([0,Math.ceil(peak/2),peak])]) {
      const y=bottom-value/peak*(bottom-22);
      node.append(svg('line',{x1:44,x2:width-14,y1:y,y2:y,stroke:'#dfe8f2','stroke-dasharray':'3 4'}),svg('text',{x:36,y:y+5,'text-anchor':'end'},compact(value)));
    }
  }
  function histogram(container,values,label,options={}) {
    values=values.filter(Number.isFinite);if(!values.length)return empty(container);
    const bins=options.bins || 10,scale=Math.max(1,...values.map(Math.abs)),normalized=values.map(value=>value/scale);
    const low=options.domain ? options.domain[0]/scale : Math.min(...normalized),high=options.domain ? options.domain[1]/scale : Math.max(...normalized);
    const same=high===low,counts=Array(bins).fill(0),range=high-low || 1;
    for(const value of normalized)counts[same ? Math.floor(bins/2) : Math.max(0,Math.min(bins-1,Math.floor((value-low)/range*bins)))]++;
    const {node,width}=frame(container,label),peak=Math.max(1,...counts),plot=width-64,barWidth=plot/bins;
    axis(node,width,peak);
    counts.forEach((count,index)=>{
      const from=same ? low*scale : (low+index/bins*range)*scale,to=same ? high*scale : (low+(index+1)/bins*range)*scale;
      const rect=svg('rect',{x:48+index*barWidth,y:200-count/peak*178,width:Math.max(2,barWidth-5),height:count/peak*178,rx:3,fill:options.color || '#7953cc','data-bin-count':count});
      rect.append(svg('title',{},`${compact(from)} – ${compact(to)}${options.suffix || ''}: ${count} observations`));node.append(rect);
    });
    node.append(svg('text',{x:44,y:235},compact(low*scale)+(options.suffix || '')),svg('text',{x:width-14,y:235,'text-anchor':'end'},compact(high*scale)+(options.suffix || '')));
    container.replaceChildren(node,element('p',`${values.length} measured values · ${same ? 'one observed value' : bins+' equal-width bins'}`,'chart-scope'));
  }
  function donut(container,items,label,onSelect) {
    items=items.filter(item=>item.count>0);const total=items.reduce((sum,item)=>sum+item.count,0);if(!total)return empty(container);
    const layout=element('div',undefined,'donut-layout'),ring=svg('svg',{viewBox:'0 0 220 230',class:'donut-chart',role:'img','aria-label':label});
    ring.append(svg('title',{},label),svg('circle',{cx:110,cy:112,r:76,fill:'none',stroke:'#e8eef6','stroke-width':28}));
    let offset=0;const length=2*Math.PI*76,legend=element('div',undefined,'donut-legend');
    for(const item of items) {
      const color=item.color || palette[item.key] || '#278bb4',portion=item.count/total;
      const arc=svg('circle',{cx:110,cy:112,r:76,fill:'none',stroke:color,'stroke-width':28,'stroke-dasharray':`${portion*length} ${length}`,'stroke-dashoffset':-offset*length,transform:'rotate(-90 110 112)'});
      arc.append(svg('title',{},`${item.label}: ${item.count} (${(portion*100).toFixed(1)}%)`));ring.append(arc);offset+=portion;
      const row=element(onSelect ? 'button':'div',undefined,'legend-row');if(onSelect){row.type='button';row.addEventListener('click',()=>onSelect(item.key));}
      const swatch=element('i',undefined,'legend-swatch');swatch.style.background=color;
      row.append(swatch,element('span',item.label),element('strong',compact(item.count)));legend.append(row);
    }
    ring.append(svg('text',{x:110,y:113,'text-anchor':'middle',class:'donut-total'},compact(total)),svg('text',{x:110,y:143,'text-anchor':'middle',class:'donut-caption'},'alerts'));
    layout.append(ring,legend);container.replaceChildren(layout);
  }
  function activity(container,records,label) {
    if(!records.length)return empty(container);
    const times=records.map(record=>Date.parse(record.timestamp)).filter(Number.isFinite);if(!times.length)return empty(container);
    const first=Math.min(...times),last=Math.max(...times),start=first===last ? first-60000:first,span=Math.max(60000,last-start+1),counts=Array(16).fill(0);
    for(const time of times)counts[Math.min(15,Math.max(0,Math.floor((time-start)/span*16)))]++;
    const {node,width}=frame(container,label),peak=Math.max(1,...counts),coords=counts.map((count,index)=>[48+index/15*(width-66),200-count/peak*178]);
    axis(node,width,peak);
    const points=coords.map(pair=>pair.join(',')).join(' ');
    node.append(svg('polygon',{points:`48,200 ${points} ${width-18},200`,fill:'#d4edfa'}),svg('polyline',{points,fill:'none',stroke:'#1989c4','stroke-width':3,'stroke-linejoin':'round'}));
    coords.forEach(([x,y],index)=>{const dot=svg('circle',{cx:x,cy:y,r:4,fill:'#1989c4'});dot.append(svg('title',{},`${new Date(start+index*span/16).toLocaleString()}: ${counts[index]} alerts`));node.append(dot);});
    const date=value=>new Date(value).toLocaleString(undefined,span>86400000 ? {month:'short',day:'numeric'}:{hour:'2-digit',minute:'2-digit'});
    node.append(svg('text',{x:44,y:235},date(start)),svg('text',{x:width-14,y:235,'text-anchor':'end'},date(last)));
    const interval=span/16, intervalLabel=interval<60000 ? `${(interval/1000).toFixed(1)} second` : `${(interval/60000).toFixed(1)} minute`;
    container.replaceChildren(node,element('p',`${times.length} alerts · detection time · ${intervalLabel} intervals`,'chart-scope'));
  }
  function bars(container,items,label,onSelect) {
    items=items.filter(item=>item.count>0).sort((a,b)=>b.count-a.count);if(!items.length)return empty(container);
    const maximum=Math.max(...items.map(item=>item.count)),list=element('div',undefined,'portal-bars');list.setAttribute('aria-label',label);
    for(const item of items) {
      const row=element('div',undefined,'portal-bar'),head=element('div',undefined,'portal-bar-label');
      const name=element(onSelect ? 'button':'span',item.label);if(onSelect){name.type='button';name.addEventListener('click',()=>onSelect(item.key));}
      head.append(name,element('strong',compact(item.count)));const track=element('div',undefined,'portal-bar-track'),fill=element('span');
      fill.style.width=item.count/maximum*100+'%';fill.style.background=item.color || palette[item.key] || '#278bb4';track.append(fill);row.append(head,track);list.append(row);
    }container.replaceChildren(list);
  }
  function sequence(container,values,label,color='#2578b9') {
    if(!values.length)return empty(container);
    const {node,width}=frame(container,label),low=Math.min(0,...values),high=Math.max(0,...values),span=high-low||1;
    const coords=values.map((value,index)=>[48+(values.length===1?.5:index/(values.length-1))*(width-66),200-(value-low)/span*178]);
    for(const value of [low,(low+high)/2,high]){const y=200-(value-low)/span*178;node.append(svg('line',{x1:48,y1:y,x2:width-18,y2:y,stroke:'#e1e8f0','stroke-dasharray':'3 4'}),svg('text',{x:40,y:y+5,'text-anchor':'end'},new Intl.NumberFormat(undefined,{maximumSignificantDigits:4}).format(value)));}
    node.append(svg('polyline',{points:coords.map(pair=>pair.join(',')).join(' '),fill:'none',stroke:color,'stroke-width':3}));
    coords.forEach(([x,y],index)=>{const dot=svg('circle',{cx:x,cy:y,r:4,fill:color});dot.append(svg('title',{},`Observation ${index+1}: ${values[index]}`));node.append(dot);});
    node.append(svg('text',{x:48,y:235},'1'),svg('text',{x:width-18,y:235,'text-anchor':'end'},String(values.length)));
    container.replaceChildren(node,element('p','Supplied sequence · observation order','chart-scope'));
  }
  function volumes(container,items,label) {
    const total=items.reduce((sum,item)=>sum+item.count,0);if(!total)return empty(container);
    const {node,width}=frame(container,label,300),peak=Math.max(1,...items.map(item=>item.count)),step=(width-66)/items.length;
    axis(node,width,peak);
    items.forEach((item,index)=>{
      const x=48+index*step,barWidth=Math.min(80,step*.65),height=item.count/peak*178;
      const rect=svg('rect',{x:x+(step-barWidth)/2,y:200-height,width:barWidth,height,rx:3,fill:item.color,'data-volume-count':item.count});
      rect.append(svg('title',{},item.label+': '+item.count+' threats'));node.append(rect);
      node.append(svg('text',{x:x+step/2,y:Math.max(18,190-height),'text-anchor':'middle'},compact(item.count)));
      const caption=svg('text',{x:x+step/2,y:228,'text-anchor':'middle'}),words=item.label.split(' ');
      const lines=words.length>1?[words.slice(0,Math.ceil(words.length/2)).join(' '),words.slice(Math.ceil(words.length/2)).join(' ')]:words;
      lines.forEach((line,i)=>caption.append(svg('tspan',{x:x+step/2,dy:i?21:0},line)));node.append(caption);
    });
    container.replaceChildren(node,element('p',total+' threats · displayed history records','chart-scope'));
  }
  return {palette,histogram,donut,activity,bars,sequence,volumes};
})();
