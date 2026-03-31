/* app.js — Payload Encoder Framework Frontend Logic */
'use strict';

// ═══════════════════════════ 3D CANVAS BACKGROUND ═══════════════════════════
(function initCanvas() {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, particles, mouse = {x: -9999, y: -9999};

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function mkParticle() {
    return {
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - .5) * .4, vy: (Math.random() - .5) * .4,
      r: Math.random() * 1.5 + .5,
      opacity: Math.random() * .5 + .1,
      color: Math.random() > .5 ? '0,229,255' : '124,77,255'
    };
  }

  function init() {
    resize();
    particles = Array.from({length: 120}, mkParticle);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 140) {
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = 'rgba(0,229,255,' + (.12 * (1 - dist / 140)) + ')';
          ctx.lineWidth = .5;
          ctx.stroke();
        }
      }

      // Mouse attraction
      const p = particles[i];
      const mdx = p.x - mouse.x, mdy = p.y - mouse.y;
      const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
      if (mdist < 180) {
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.strokeStyle = 'rgba(' + p.color + ',' + (.25 * (1 - mdist / 180)) + ')';
        ctx.lineWidth = .8;
        ctx.stroke();
      }
    }

    // Draw particles
    particles.forEach(function(p) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(' + p.color + ',' + p.opacity + ')';
      ctx.fill();

      // Glow
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r * 3, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(' + p.color + ',.03)';
      ctx.fill();
    });

    requestAnimationFrame(draw);
  }

  window.addEventListener('resize', init);
  document.addEventListener('mousemove', function(e) { mouse.x = e.clientX; mouse.y = e.clientY; });
  init();
  draw();
})();

// ═══════════════════════════ 3D TILT ON CARDS ═══════════════════════════════
document.addEventListener('mousemove', function(e) {
  document.querySelectorAll('.tc').forEach(function(card) {
    var rect = card.getBoundingClientRect();
    var cx = rect.left + rect.width / 2;
    var cy = rect.top + rect.height / 2;
    var dx = (e.clientX - cx) / (rect.width / 2);
    var dy = (e.clientY - cy) / (rect.height / 2);
    var dist = Math.sqrt(dx*dx + dy*dy);
    if (dist < 1.5) {
      card.style.transform = 'perspective(600px) rotateY(' + (dx*6) + 'deg) rotateX(' + (-dy*6) + 'deg) translateZ(4px)';
      card.style.setProperty('--mx', ((dx + 1) / 2 * 100) + '%');
      card.style.setProperty('--my', ((dy + 1) / 2 * 100) + '%');
    } else {
      card.style.transform = '';
    }
  });
});

// ═══════════════════════════ ANIMATED COUNTER ════════════════════════════════
function animCount(el, target, duration) {
  var start = 0, step = target / (duration / 16);
  var timer = setInterval(function() {
    start = Math.min(start + step, target);
    el.textContent = Math.round(start);
    if (start >= target) clearInterval(timer);
  }, 16);
}

// ═══════════════════════════ STATE ══════════════════════════════════════════
var techniques = [], mutations = [], selTech = {}, selMut = {}, lastReport = null;
var QUICK = [
  "' OR 1=1 --", "' UNION SELECT username,pass FROM users --",
  "admin' --", "1'; DROP TABLE users --",
  "<script>alert('XSS')<\/script>", "../../etc/passwd"
];

// ═══════════════════════════ BOOTSTRAP ══════════════════════════════════════
window.addEventListener('load', function() {
  loadTechniques(); loadMutations(); loadStats();
  loadRules(); loadSamples();
  buildPills('encPills', 'encPayload');
  buildPills('mutPills', 'mutPayload');
  buildPills('batchPills', 'batchPayload');

  // Cold-start detection: ping the API and show overlay if slow / 503
  var coldStartDone = false;
  var COLD_TIMEOUT = 8000; // show overlay if no response in 8s
  var coldTimer = setTimeout(function() {
    if (!coldStartDone) showColdStartOverlay();
  }, COLD_TIMEOUT);

  fetch('/api/waf/stats')
    .then(function(r) {
      coldStartDone = true;
      clearTimeout(coldTimer);
      if (r.status === 503) { showColdStartOverlay(); }
      else { hideColdStartOverlay(); }
    })
    .catch(function() {
      coldStartDone = true;
      clearTimeout(coldTimer);
      showColdStartOverlay();
    });
});

function showColdStartOverlay() {
  var el = document.getElementById('coldStartOverlay');
  if (!el) return;
  el.style.display = 'flex';
  var remaining = 18;
  var timerEl = document.getElementById('coldStartTimer');
  var interval = setInterval(function() {
    remaining--;
    if (timerEl) timerEl.textContent = remaining + 's';
    if (remaining <= 0) {
      clearInterval(interval);
      hideColdStartOverlay();
      // Retry data load after cold start
      loadTechniques(); loadMutations(); loadStats();
      loadRules(); loadSamples();
    }
  }, 1000);
}

function hideColdStartOverlay() {
  var el = document.getElementById('coldStartOverlay');
  if (el) el.style.display = 'none';
}

// ═══════════════════════════ TABS ════════════════════════════════════════════
function switchTab(name) {
  var map = ['encoder','decoder','mutations','batch','rules','aiwaf','livetest','mllab','metrics','crs','cloudwaf','dataset','samples'];
  document.querySelectorAll('.tab').forEach(function(t,i){ t.classList.toggle('active', map[i]===name); });
  document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
  document.getElementById('panel-'+name).classList.add('active');
}

// ═══════════════════════════ STATS ══════════════════════════════════════════
async function loadStats() {
  var res = await fetch('/api/waf/stats');
  var s = await res.json();
  var data = [
    {n: techniques.length||10, l:'Encoding Tech', c:'0,229,255'},
    {n: 6, l:'Mutations', c:'124,77,255'},
    {n: s.total_inspected||0, l:'Inspections', c:'0,229,255'},
    {n: s.total_blocked||0, l:'Blocked', c:'255,71,87'},
    {n: (s.rules||[]).length, l:'WAF Rules', c:'0,255,157'}
  ];
  var html = data.map(function(d) {
    return '<div class="sbox"><div class="n" data-target="'+d.n+'">0</div><div class="l">'+d.l+'</div>' +
      '<div class="glow" style="background:rgba('+d.c+',.4)"></div></div>';
  }).join('');
  var row = document.getElementById('statsRow');
  row.innerHTML = html;
  row.querySelectorAll('.n').forEach(function(el) {
    animCount(el, parseInt(el.dataset.target), 800);
  });
}

// ═══════════════════════════ TECHNIQUES ════════════════════════════════════
async function loadTechniques() {
  var res = await fetch('/api/techniques');
  techniques = await res.json();
  var html = '';
  techniques.forEach(function(t) {
    var on = selTech[t.id] ? ' on' : '';
    var chk = selTech[t.id] ? '&#x2713;' : '';
    var bdg = t.category === 'encoding' ? 'bdg-e' : 'bdg-o';
    html += '<div class="tc'+on+'" onclick="toggleTech(\''+t.id+'\',this)">'+
      '<div class="chk">'+chk+'</div>'+
      '<div class="name">'+esc(t.name)+' <span class="bdg '+bdg+'">'+t.category+'</span></div>'+
      '<div class="desc">'+esc(t.description)+'</div></div>';
  });
  document.getElementById('techGrid').innerHTML = html;
}

function toggleTech(id, el) {
  if (selTech[id]) { delete selTech[id]; el.classList.remove('on'); el.querySelector('.chk').innerHTML=''; }
  else { selTech[id]=true; el.classList.add('on'); el.querySelector('.chk').innerHTML='&#x2713;'; }
}
function selectAll(g) {
  if(g==='tech'){techniques.forEach(function(t){selTech[t.id]=true;}); loadTechniques();}
  else {mutations.forEach(function(m){selMut[m.id]=true;}); loadMutations();}
}
function clearAll(g) {
  if(g==='tech'){selTech={}; loadTechniques();}
  else{selMut={}; loadMutations();}
}

// ═══════════════════════════ MUTATIONS ═════════════════════════════════════
async function loadMutations() {
  var res = await fetch('/api/mutations');
  mutations = await res.json();
  var html = '';
  mutations.forEach(function(m) {
    var on = selMut[m.id] ? ' on' : '';
    var chk = selMut[m.id] ? '&#x2713;' : '';
    html += '<div class="tc'+on+'" onclick="toggleMut(\''+m.id+'\',this)">'+
      '<div class="chk">'+chk+'</div>'+
      '<div class="name">'+esc(m.name)+' <span class="bdg bdg-m">mutation</span></div>'+
      '<div class="desc">'+esc(m.description)+'</div></div>';
  });
  document.getElementById('mutGrid').innerHTML = html;
}
function toggleMut(id, el) {
  if(selMut[id]){delete selMut[id]; el.classList.remove('on'); el.querySelector('.chk').innerHTML='';}
  else{selMut[id]=true; el.classList.add('on'); el.querySelector('.chk').innerHTML='&#x2713;';}
}

// ═══════════════════════════ PILLS ═════════════════════════════════════════
function buildPills(cid, tid) {
  var c = document.getElementById(cid);
  c.innerHTML = QUICK.map(function(p) {
    return '<div class="pill" onclick="document.getElementById(\''+tid+'\').value=this.dataset.v" data-v="'+escAttr(p)+'">'+esc(p.substring(0,25))+'</div>';
  }).join('');
}

// ═══════════════════════════ ENCODE ════════════════════════════════════════
async function encodePayload() {
  var payload = document.getElementById('encPayload').value.trim();
  if (!payload) { toast('&#x26A0;&#xFE0F; Enter a payload'); return; }
  var techs = Object.keys(selTech).length ? Object.keys(selTech) : techniques.map(function(t){return t.id;});
  var results = [];
  for (var i=0; i<techs.length; i++) {
    var res = await fetch('/api/encode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload,technique:techs[i]})});
    var d = await res.json();
    if(d.success) results.push({r:d.result,w:null});
  }
  renderEncResults(results, false);
}

async function encodeAndTest() {
  var payload = document.getElementById('encPayload').value.trim();
  if (!payload) { toast('&#x26A0;&#xFE0F; Enter a payload'); return; }
  var techs = Object.keys(selTech).length ? Object.keys(selTech) : techniques.map(function(t){return t.id;});
  var results = [];
  for (var i=0; i<techs.length; i++) {
    var er = await fetch('/api/encode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload,technique:techs[i]})});
    var ed = await er.json();
    if(!ed.success) continue;
    var tr = await fetch('/api/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:ed.result.encoded})});
    var td = await tr.json();
    results.push({r:ed.result, w:td.success?td.result:null});
  }
  // chain variants
  for(var i=0; i<Math.min(4,techs.length-1); i++) {
    var chain=[techs[i],techs[(i+1)%techs.length]];
    var er=await fetch('/api/chain-encode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload,techniques:chain})});
    var ed=await er.json();
    if(!ed.success) continue;
    var tr=await fetch('/api/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:ed.result.encoded})});
    var td=await tr.json();
    results.push({r:ed.result,w:td.success?td.result:null});
  }
  renderEncResults(results, true);
  loadStats();
}

function renderEncResults(results, withWAF) {
  document.getElementById('encCard').style.display='block';
  if(document.getElementById('encEmptyState')) document.getElementById('encEmptyState').style.display='none';
  if(document.getElementById('encTableWrap')) document.getElementById('encTableWrap').style.display='block';
  document.getElementById('encSub').textContent = results.length+' variants'+(withWAF?' \u00b7 WAF tested':'');
  var html='';
  results.forEach(function(item,i){
    var r=item.r, w=item.w;
    var st=!withWAF?'&#x2014;':(w&&w.detected?'<span class="st-blocked">&#x1F6AB; BLOCKED</span>':'<span class="st-bypassed">&#x2705; BYPASSED</span>');
    var conf=w?Math.round(w.confidence*100)+'%':'&#x2014;';
    var label=esc(r.label||(r.techniques_applied||[]).join(' > '));
    html+='<tr><td>'+(i+1)+'</td><td>'+st+'</td><td><code>'+label+'</code></td>'+
      '<td><code>'+esc((r.encoded||'').substring(0,100))+'</code></td><td>'+conf+'</td>'+
      '<td><button class="cp" onclick="copyText(\''+escAttr(r.encoded)+'\')">&#x1F4CB;</button></td></tr>';
  });
  document.getElementById('encBody').innerHTML=html;
}

// ═══════════════════════════ DECODE ════════════════════════════════════════
async function decodePayload() {
  var payload=document.getElementById('decPayload').value.trim();
  if(!payload){toast('Enter an encoded payload');return;}
  var type=document.getElementById('decType').value;
  var res=await fetch('/api/decode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload,encoding_type:type})});
  var d=await res.json();
  if(!d.success){toast('Decode failed');return;}
  var result=d.result;
  document.getElementById('decCard').style.display='block';
  if(document.getElementById('decEmptyState')) document.getElementById('decEmptyState').style.display='none';
  if(document.getElementById('decResultWrap')) document.getElementById('decResultWrap').style.display='block';
  document.getElementById('decSub').textContent=result.total_layers+' layer(s) \u00b7 '+(result.fully_decoded?'Fully decoded':'Partial decode');
  var stepsHtml='';
  (result.steps||[]).forEach(function(s){
    stepsHtml+='<div class="dstep"><div class="dstep-h">'+
      '<span style="color:var(--c1);font-size:11px;font-weight:700">Layer '+s.step+'</span>'+
      '<span style="color:var(--c2);font-size:11px">'+esc(s.encoding_detected)+'</span>'+
      '<span style="color:var(--text3);font-size:11px">'+Math.round(s.confidence*100)+'% conf</span>'+
      '</div><pre>'+esc(s.input)+'</pre></div>'+
      '<div style="text-align:center;color:var(--text3);margin:4px 0;font-size:20px">&#x2193;</div>';
  });
  document.getElementById('decSteps').innerHTML=stepsHtml;
  document.getElementById('decFinal').textContent=result.final_decoded;
}

async function detectOnly() {
  var payload=document.getElementById('decPayload').value.trim();
  if(!payload){toast('Enter a payload');return;}
  var res=await fetch('/api/detect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload})});
  var d=await res.json();
  document.getElementById('detectCard').style.display='block';
  var html='';
  if(!d.detections||!d.detections.length){html='<p style="color:var(--text3);text-align:center;padding:16px">No encodings detected</p>';}
  else{d.detections.forEach(function(det){
    html+='<div class="det-row"><div><strong>'+esc(det.name)+'</strong><div style="font-size:11px;color:var(--text3)">'+det.matches_found+' match(es)</div></div>'+
      '<div class="det-conf">'+Math.round(det.confidence*100)+'%</div></div>';
  });}
  document.getElementById('detectOut').innerHTML=html;
}

function sendToEncoder(){
  document.getElementById('encPayload').value=document.getElementById('decFinal').textContent;
  switchTab('encoder'); toast('Loaded into Encoder Studio');
}

// ═══════════════════════════ MUTATIONS ═════════════════════════════════════
async function mutateSingle(){
  var payload=document.getElementById('mutPayload').value.trim();
  if(!payload){toast('Enter a payload');return;}
  var muts=Object.keys(selMut).length?Object.keys(selMut):mutations.map(function(m){return m.id;});
  var results=[];
  for(var i=0;i<muts.length;i++){
    var res=await fetch('/api/mutate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload,mutation_type:muts[i]})});
    var d=await res.json();
    if(d.success) results.push({r:d.result,w:null});
  }
  renderMutResults(results,false);
}

async function mutateAndTest(){
  var payload=document.getElementById('mutPayload').value.trim();
  if(!payload){toast('Enter a payload');return;}
  var muts=Object.keys(selMut).length?Object.keys(selMut):mutations.map(function(m){return m.id;});
  var results=[];
  for(var i=0;i<muts.length;i++){
    var mr=await fetch('/api/mutate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload,mutation_type:muts[i]})});
    var md=await mr.json();
    if(!md.success) continue;
    var tr=await fetch('/api/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:md.result.mutated})});
    var td=await tr.json();
    results.push({r:md.result,w:td.success?td.result:null});
  }
  renderMutResults(results,true); loadStats();
}

function renderMutResults(results,withWAF){
  document.getElementById('mutCard').style.display='block';
  if(document.getElementById('mutEmptyState')) document.getElementById('mutEmptyState').style.display='none';
  if(document.getElementById('mutTableWrap')) document.getElementById('mutTableWrap').style.display='block';
  if(document.getElementById('mutSub')) document.getElementById('mutSub').textContent = results.length+' variants'+(withWAF?' \u00b7 WAF tested':'');
  var html='';
  results.forEach(function(item,i){
    var r=item.r,w=item.w;
    var st=!withWAF?'&#x2014;':(w&&w.detected?'<span class="st-blocked">&#x1F6AB; BLOCKED</span>':'<span class="st-bypassed">&#x2705; BYPASSED</span>');
    var conf=w?Math.round(w.confidence*100)+'%':'&#x2014;';
    html+='<tr><td>'+(i+1)+'</td><td>'+st+'</td><td><code>'+esc(r.mutation_type)+'</code></td>'+
      '<td><code>'+esc((r.mutated||'').substring(0,100))+'</code></td><td>'+conf+'</td>'+
      '<td><button class="cp" onclick="copyText(\''+escAttr(r.mutated)+'\')">&#x1F4CB;</button></td></tr>';
  });
  document.getElementById('mutBody').innerHTML=html;
}

// ═══════════════════════════ BATCH TEST ════════════════════════════════════
async function runBatch(){
  var payload=document.getElementById('batchPayload').value.trim();
  var count=parseInt(document.getElementById('batchCount').value)||15;
  if(!payload){toast('Enter a payload');return;}
  var res=await fetch('/api/batch-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload,count:count})});
  var d=await res.json();
  if(!d.success){toast('Batch test failed');return;}
  lastReport=d.report;
  var r=d.report;
  document.getElementById('batchOut').style.display='block';
  document.getElementById('bFill').style.width=r.evasion_rate+'%';
  animCount(document.querySelector('#bRate span'),Math.round(r.evasion_rate*100)/100,800);
  animCount(document.getElementById('bBlocked'),r.total_blocked,600);
  animCount(document.getElementById('bBypassed'),r.total_bypassed,600);
  animCount(document.getElementById('bTotal'),r.total_tested,400);
  var html='';
  (r.results||[]).forEach(function(result,i){
    var p=result.payload;
    var st=result.status==='BLOCKED'?'<span class="st-blocked">&#x1F6AB; BLOCKED</span>':'<span class="st-bypassed">&#x2705; BYPASSED</span>';
    var label=esc(p.label||(p.techniques_applied||[]).join(' > '));
    var conf=result.confidence?Math.round(result.confidence*100)+'%':'&#x2014;';
    html+='<tr><td>'+(i+1)+'</td><td>'+st+'</td><td><code>'+label+'</code></td>'+
      '<td><code>'+esc((p.encoded||'').substring(0,100))+'</code></td><td>'+conf+'</td>'+
      '<td><button class="cp" onclick="copyText(\''+escAttr(p.encoded)+'\')">&#x1F4CB;</button></td></tr>';
  });
  document.getElementById('batchBody').innerHTML=html;
  loadStats();
}

// ═══════════════════════════ EXPORT ════════════════════════════════════════
function toggleExport(){document.getElementById('exMenu').classList.toggle('show');}
document.addEventListener('click',function(e){if(!e.target.closest('.exd')){var m=document.getElementById('exMenu');if(m)m.classList.remove('show');}});

async function exportReport(fmt){
  if(!lastReport){toast('Run a batch test first');return;}
  document.getElementById('exMenu').classList.remove('show');
  var body=fmt==='csv'?JSON.stringify({results:lastReport.results}):JSON.stringify({report:lastReport});
  var res=await fetch('/api/export/'+fmt,{method:'POST',headers:{'Content-Type':'application/json'},body:body});
  var blob=await res.blob();
  var url=URL.createObjectURL(blob);
  var a=document.createElement('a');
  a.href=url; a.download='evasion_report.'+fmt; a.click();
  URL.revokeObjectURL(url);
  toast('Exported as '+fmt.toUpperCase());
}

// ═══════════════════════════ WAF RULES ═════════════════════════════════════
async function loadRules(){
  var res=await fetch('/api/waf/rules');
  var rules=await res.json();
  var html='';
  rules.forEach(function(r){
    var on=r.enabled?' on':'';
    var isDefault=r.rule_id.startsWith('WAF-');
    var delBtn=isDefault?'':'<button class="btn btn-o btn-sm" style="color:var(--red);border-color:rgba(255,71,87,.3)" onclick="deleteRule(\''+r.rule_id+'\')">&#x2715;</button>';
    html+='<div class="rcrd"><div><div><span class="rule-id">'+esc(r.rule_id)+'</span><strong>'+esc(r.category)+'</strong></div><p>'+esc(r.description)+'</p></div>'+
      '<div style="display:flex;align-items:center;gap:10px">'+
        '<span class="hits-badge">'+(r.hit_count||0)+' hits</span>'+
        '<div class="tog'+on+'" onclick="toggleRule(\''+r.rule_id+'\','+(!r.enabled)+',this)"><div class="knob"></div></div>'+
        delBtn+'</div></div>';
  });
  document.getElementById('rulesList').innerHTML=html||'<p style="color:var(--text3);text-align:center;padding:20px">No rules loaded</p>';
}

async function toggleRule(id,enable,el){
  await fetch('/api/waf/toggle-rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rule_id:id,enabled:enable})});
  if(enable)el.classList.add('on');else el.classList.remove('on');
}

async function deleteRule(id){
  var res=await fetch('/api/waf/delete-rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rule_id:id})});
  var d=await res.json();
  if(d.success){toast('Rule '+id+' deleted');loadRules();loadStats();}
  else toast('Failed to delete');
}

async function addRule(){
  var id=document.getElementById('nRuleId').value.trim();
  var cat=document.getElementById('nRuleCat').value.trim()||'Custom';
  var desc=document.getElementById('nRuleDesc').value.trim();
  var pats=document.getElementById('nRulePat').value.trim();
  var conf=parseFloat(document.getElementById('nRuleConf').value)||.8;
  if(!id||!pats){toast('Rule ID and patterns required');return;}
  var patterns=pats.split('\n').map(function(p){return p.trim();}).filter(Boolean);
  var res=await fetch('/api/waf/add-rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rule_id:id,category:cat,description:desc,patterns:patterns,confidence:conf})});
  var d=await res.json();
  if(d.success){
    toast('&#x2705; Rule '+id+' added!');
    ['nRuleId','nRuleDesc','nRulePat'].forEach(function(x){document.getElementById(x).value='';});
    loadRules();loadStats();
  }else toast(d.message||'Failed');
}

function testPattern(){
  var pats=document.getElementById('nRulePat').value.trim();
  if(!pats){toast('Enter patterns first');return;}
  var patterns=pats.split('\n').map(function(p){return p.trim();}).filter(Boolean);
  var tests=["' OR 1=1 --","<script>alert(1)<\/script>","../../etc/passwd","; cat /etc/passwd","Hello World"];
  var html='<table class="tbl"><thead><tr><th>Test Payload</th><th>Result</th></tr></thead><tbody>';
  tests.forEach(function(p){
    var matched=false;
    patterns.forEach(function(pat){try{if(new RegExp(pat,'i').test(p))matched=true;}catch(e){}});
    html+='<tr><td><code>'+esc(p)+'</code></td><td>'+(matched?'<span class="st-blocked">&#x2713; MATCH</span>':'<span style="color:var(--text3)">&#x2014;</span>')+'</td></tr>';
  });
  html+='</tbody></table>';
  document.getElementById('patTestCard').style.display='block';
  document.getElementById('patTestOut').innerHTML=html;
}

// ═══════════════════════════ SAMPLES ═══════════════════════════════════════
async function loadSamples(){
  var res=await fetch('/api/samples?category=all');
  var samples=await res.json();
  var icons={sqli:'&#x1F489;',xss:'&#x1F3AF;',cmdi:'&#x2699;&#xFE0F;',path_traversal:'&#x1F4C1;',header_injection:'&#x1F4E8;',ssrf:'&#x1F310;',xxe:'&#x1F4C4;',ldap_injection:'&#x1F5C2;',template_injection:'&#x1F9E9;',open_redirect:'&#x21AA;&#xFE0F;'};
  var names={sqli:'SQL Injection',xss:'XSS',cmdi:'Command Injection',path_traversal:'Path Traversal',header_injection:'Header Injection',ssrf:'SSRF',xxe:'XXE Injection',ldap_injection:'LDAP Injection',template_injection:'Template Injection',open_redirect:'Open Redirect'};
  var html='';
  Object.keys(samples).forEach(function(cat){
    html+='<div class="scat"><h4>'+(icons[cat]||'')+ ' '+(names[cat]||cat)+'</h4>';
    samples[cat].forEach(function(p){
      html+='<div class="sitm" onclick="loadSample(this)" data-payload="'+escAttr(p)+'">'+
        '<span>'+esc(p.substring(0,80))+'</span>'+
        '<button class="cp" onclick="event.stopPropagation();copyText(this.closest(\'.sitm\').dataset.payload)">&#x1F4CB;</button></div>';
    });
    html+='</div>';
  });
  document.getElementById('samplesOut').innerHTML=html;
}

function loadSample(el){
  document.getElementById('encPayload').value=el.dataset.payload;
  switchTab('encoder'); toast('Loaded');
}

// ═══════════════════════════ UTILS ═════════════════════════════════════════
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function escAttr(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\r?\n/g,'\\n');}
function copyText(t){navigator.clipboard.writeText(t).then(function(){toast('&#x1F4CB; Copied!');}).catch(function(){toast('Failed');});}
function copyEl(id){var el=document.getElementById(id);if(el)copyText(el.textContent||el.innerText);}
function toast(msg){var t=document.createElement('div');t.className='toast';t.innerHTML=msg;document.body.appendChild(t);setTimeout(function(){t.style.opacity='0';t.style.transform='translateY(10px)';setTimeout(function(){t.remove();},300);},2200);}

// ═══════════════════════════ AI WAF ════════════════════════════════════════
async function aiClassify(){
  var payload=document.getElementById('aiPayload').value.trim();
  if(!payload){toast('Enter a payload first');return;}

  // Show loading state inside result panel
  var resultEl = document.getElementById('aiResult');
  resultEl.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px;gap:14px"><div style="width:36px;height:36px;border:3px solid rgba(56,189,248,.2);border-top-color:var(--c1);border-radius:50%;animation:spin 1s linear infinite"></div><div style="color:var(--text2);font-size:13px">Classifying payload…</div></div>';

  var res=await fetch('/api/ai-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload})});
  var d=await res.json();
  if(!d.success){toast('AI classify failed');return;}
  var r=d.results[0];
  var isAtk=r.label==='ATTACK';
  var col=isAtk?'255,71,87':'0,255,157';
  var lbl=isAtk?'&#x1F6AB; ATTACK':'&#x2705; CLEAN';
  var feats=(r.features_matched||[]).map(function(f){return '<span style="background:rgba('+col+',.15);color:rgba('+col+',1);padding:3px 8px;border-radius:4px;font-size:11px;margin:3px;display:inline-block">'+esc(f)+'</span>';}).join('');
  var html='<div style="text-align:center;padding:20px">'+
    '<div style="font-size:28px;font-weight:700;color:rgba('+col+',1);margin-bottom:8px">'+lbl+'</div>'+
    '<div style="font-size:14px;color:rgba('+col+',.8);margin-bottom:20px">Confidence: '+r.confidence+'%</div>'+
    '<div style="display:flex;gap:20px;justify-content:center;margin-bottom:20px">'+
      '<div style="text-align:center"><div style="font-size:22px;font-weight:700;color:#ef4444">'+r.attack_probability+'%</div><div style="font-size:11px;color:var(--text3)">ATTACK prob</div></div>'+
      '<div style="text-align:center"><div style="font-size:22px;font-weight:700;color:#22c55e">'+r.clean_probability+'%</div><div style="font-size:11px;color:var(--text3)">CLEAN prob</div></div>'+
    '</div>'+
    '<div style="margin-bottom:12px;font-size:12px;color:var(--text3);font-weight:600;letter-spacing:.08em">MATCHED SIGNATURES</div>'+
    '<div>'+(feats||'<span style="color:var(--text3);font-size:12px">No specific signatures matched</span>')+'</div>'+
  '</div>';
  resultEl.innerHTML=html;
}

async function aiStats(){
  var res=await fetch('/api/ai-stats');
  var d=await res.json();
  if(!d.success){toast('Failed to load AI stats');return;}
  var s=d.stats;
  var html='<table class="tbl"><tbody>'+
    '<tr><td>Model Type</td><td><code>'+esc(s.model_type)+'</code></td></tr>'+
    '<tr><td>Training Samples</td><td>'+s.training_samples+'</td></tr>'+
    '<tr><td>Attack Samples</td><td>'+s.attack_samples+'</td></tr>'+
    '<tr><td>Clean Samples</td><td>'+s.clean_samples+'</td></tr>'+
    '<tr><td>CV Accuracy</td><td><strong style="color:var(--g1)">'+s.train_accuracy_pct+'%</strong></td></tr>'+
    '<tr><td>Model Trained</td><td>'+(s.trained?'&#x2705; Yes':'&#x274C; No')+'</td></tr>'+
  '</tbody></table>';
  document.getElementById('aiStatsContent').innerHTML=html;
  document.getElementById('aiStatsCard').style.display='block';
}

// ═══════════════════════════ LIVE TEST ══════════════════════════════════════
var _liveAuthorized=false;

function startLiveTest(){
  if(!_liveAuthorized){
    document.getElementById('liveDisclaimerModal').style.display='flex';
    return;
  }
  _runLiveTest();
}

function acceptDisclaimer(){
  if(!document.getElementById('authConfirm').checked){
    toast('&#x26A0;&#xFE0F; You must check the authorization checkbox');return;
  }
  document.getElementById('liveDisclaimerModal').style.display='none';
  _liveAuthorized=true;
  _runLiveTest();
}

async function validateLiveUrl(){
  var url=document.getElementById('liveUrlTemplate').value.trim();
  if(!url){toast('Enter a URL template');return;}
  var res=await fetch('/api/live-validate-url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url_template:url})});
  var d=await res.json();
  var el=document.getElementById('liveUrlStatus');
  if(d.valid){
    el.innerHTML='<span style="color:#22c55e">&#x2705; Valid URL template</span>';
  }else{
    el.innerHTML='<span style="color:#ef4444">&#x274C; '+esc(d.message)+'</span>';
  }
}

async function _runLiveTest(){
  var url=document.getElementById('liveUrlTemplate').value.trim();
  var payload=document.getElementById('livePayload').value.trim();
  var count=parseInt(document.getElementById('liveCount').value)||15;
  var rate=parseFloat(document.getElementById('liveRate').value)||2;
  var method=document.getElementById('liveMethod').value;
  if(!url||!payload){toast('&#x26A0;&#xFE0F; URL template and payload required');return;}
  document.getElementById('liveResults').innerHTML='<div style="text-align:center;padding:30px;color:var(--c1)">&#x23F3; Running live test... '+count+' variants at '+rate+' req/sec</div>';
  document.getElementById('liveSummary').innerHTML='';
  var res=await fetch('/api/live-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url_template:url,payload:payload,count:count,rate_per_second:rate,method:method,authorized:true})});
  var d=await res.json();
  if(!d.success){toast('&#x274C; '+esc(d.message));document.getElementById('liveResults').innerHTML='<div class="sub" style="color:#ef4444">Error: '+esc(d.message)+'</div>';return;}
  var r=d.report;
  var sumHtml='<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">'+
    '<div style="flex:1;min-width:100px;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);border-radius:8px;padding:16px;text-align:center">'+
      '<div style="font-size:26px;font-weight:700;color:#22c55e">'+r.evasion_rate_pct+'%</div><div style="font-size:11px;color:var(--text3)">EVASION RATE</div></div>'+
    '<div style="flex:1;min-width:100px;background:rgba(0,229,255,.07);border:1px solid rgba(0,229,255,.2);border-radius:8px;padding:16px;text-align:center">'+
      '<div style="font-size:26px;font-weight:700;color:var(--c1)">'+r.total_fired+'</div><div style="font-size:11px;color:var(--text3)">TOTAL FIRED</div></div>'+
    '<div style="flex:1;min-width:100px;background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:16px;text-align:center">'+
      '<div style="font-size:26px;font-weight:700;color:#22c55e">'+r.bypassed+'</div><div style="font-size:11px;color:var(--text3)">BYPASSED</div></div>'+
    '<div style="flex:1;min-width:100px;background:rgba(255,71,87,.07);border:1px solid rgba(255,71,87,.2);border-radius:8px;padding:16px;text-align:center">'+
      '<div style="font-size:26px;font-weight:700;color:#ef4444">'+r.blocked+'</div><div style="font-size:11px;color:var(--text3)">BLOCKED</div></div>'+
    '<div style="flex:1;min-width:100px;background:rgba(124,77,255,.07);border:1px solid rgba(124,77,255,.2);border-radius:8px;padding:16px;text-align:center">'+
      '<div style="font-size:22px;font-weight:700;color:var(--c2)">'+r.duration_seconds+'s</div><div style="font-size:11px;color:var(--text3)">DURATION</div></div>'+
  '</div>';
  document.getElementById('liveSummary').innerHTML=sumHtml;
  var html='<table class="tbl"><thead><tr><th>#</th><th>Status</th><th>Technique</th><th>HTTP</th><th>Time(ms)</th><th>Block Reason</th></tr></thead><tbody>';
  (r.results||[]).forEach(function(res,i){
    var st=res.bypassed?'<span class="st-bypassed">&#x2705; BYPASSED</span>':'<span class="st-blocked">&#x1F6AB; BLOCKED</span>';
    html+='<tr><td>'+(i+1)+'</td><td>'+st+'</td><td><code>'+esc(res.technique.substring(0,40))+'</code></td>'+
      '<td><code>'+res.status_code+'</code></td><td>'+res.response_time_ms+'</td>'+
      '<td style="color:var(--text3);font-size:11px">'+esc(res.block_reason||'—')+'</td></tr>';
  });
  html+='</tbody></table>';
  document.getElementById('liveResults').innerHTML=html;
}

// ═══════════════════════════ CLOUD WAF ══════════════════════════════════════
async function cloudWafTest() {
  var provider = document.getElementById('cloudWafProvider').value;
  var payload = document.getElementById('cloudWafPayload').value.trim();
  var count = parseInt(document.getElementById('cloudWafCount').value) || 20;
  
  if (!payload) { toast('Enter a payload'); return; }
  
  // Show loading
  document.getElementById('cloudWafEmpty').style.display = 'none';
  document.getElementById('cloudWafOut').style.display = 'block';
  document.getElementById('cloudWafSummary').innerHTML = '<div class="sub">Testing against ' + provider.toUpperCase() + ' simulator...</div>';
  document.getElementById('cloudWafResults').innerHTML = '';
  
  var res = await fetch('/api/waf/cloud/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      waf_type: provider,
      payload: payload,
      count: count
    })
  });
  
  var d = await res.json();
  if (!d.success) {
    toast('Cloud WAF test failed');
    return;
  }
  
  var r = d.report;
  var tmap = d.technique_map || {};
  
  // Build Summary
  var sumHtml = '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">' +
    '<div style="flex:1;min-width:100px;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);border-radius:8px;padding:16px;text-align:center">' +
      '<div style="font-size:26px;font-weight:700;color:#22c55e">' + (Math.round(r.bypass_rate * 10) / 10) + '%</div><div style="font-size:11px;color:var(--text3)">EVASION RATE</div></div>' +
    '<div style="flex:1;min-width:100px;background:rgba(0,229,255,.07);border:1px solid rgba(0,229,255,.2);border-radius:8px;padding:16px;text-align:center">' +
      '<div style="font-size:26px;font-weight:700;color:var(--c1)">' + r.total_tested + '</div><div style="font-size:11px;color:var(--text3)">TOTAL TESTED</div></div>' +
    '<div style="flex:1;min-width:100px;background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:16px;text-align:center">' +
      '<div style="font-size:26px;font-weight:700;color:#22c55e">' + r.bypassed + '</div><div style="font-size:11px;color:var(--text3)">BYPASSED</div></div>' +
    '<div style="flex:1;min-width:100px;background:rgba(255,71,87,.07);border:1px solid rgba(255,71,87,.2);border-radius:8px;padding:16px;text-align:center">' +
      '<div style="font-size:26px;font-weight:700;color:#ef4444">' + r.blocked + '</div><div style="font-size:11px;color:var(--text3)">BLOCKED</div></div>' +
  '</div>';
  document.getElementById('cloudWafSummary').innerHTML = sumHtml;
  
  // Build Results Table
  var html = '';
  (r.results || []).forEach(function(res, i) {
    var st = !res.blocked ? '<span class="st-bypassed">&#x2705; BYPASSED</span>' : '<span class="st-blocked">&#x1F6AB; BLOCKED</span>';
    var tech = esc(tmap[res.payload] || 'Unknown');
    html += '<tr><td>' + (i + 1) + '</td><td>' + st + '</td><td><code>' + tech + '</code></td>' +
      '<td><code style="word-break:break-all">' + esc(res.payload.substring(0, 100)) + '</code></td><td>' + res.response_time_ms + 'ms</td></tr>';
  });
  document.getElementById('cloudWafResults').innerHTML = html;
  
  loadStats();
}

// ═══════════════════════════ MATRIX RAIN ════════════════════════════════════
(function initMatrix() {
  var CHARS = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ#$%@!<>/\\[]{}';

  function makeRain(canvasId) {
    var c = document.getElementById(canvasId);
    if (!c) return;
    var ctx = c.getContext('2d');
    var fontSize = 11;

    function resize() {
      c.width  = c.offsetWidth  || 36;
      c.height = c.offsetHeight || window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    var cols = Math.floor(c.width / fontSize) || 1;
    var drops = Array.from({length: cols}, function() {
      return Math.random() * -100;
    });

    function draw() {
      ctx.fillStyle = 'rgba(2,6,23,0.18)';
      ctx.fillRect(0, 0, c.width, c.height);

      ctx.font = fontSize + 'px JetBrains Mono, monospace';

      drops.forEach(function(y, i) {
        var ch = CHARS[Math.floor(Math.random() * CHARS.length)];
        var bright = (y * fontSize > c.height * 0.75);
        ctx.fillStyle = bright ? 'rgba(0,229,255,0.9)' : 'rgba(0,229,255,0.35)';
        ctx.fillText(ch, i * fontSize, y * fontSize);

        if (y * fontSize > c.height && Math.random() > 0.95) drops[i] = 0;
        drops[i] += 0.5;
      });
    }
    setInterval(draw, 60);
  }

  makeRain('matrix-left');
  makeRain('matrix-right');
})();

// ═══════════════════════════ TEXT SCRAMBLE / GLITCH ══════════════════════════
(function initTextScramble() {
  var GLITCH_CHARS = '!<>-_\\/[]{}—=+*^?#@$%&ABCDEFXYZabcxyz0123456789';

  function scramble(el, finalText, duration) {
    el.setAttribute('data-text', finalText);
    el.classList.add('glitching');

    var totalFrames = Math.ceil(duration / 40);
    var frame = 0;
    var revealed = 0;

    var timer = setInterval(function() {
      frame++;
      revealed = Math.floor((frame / totalFrames) * finalText.length);

      var display = '';
      for (var i = 0; i < finalText.length; i++) {
        if (i < revealed) {
          display += finalText[i];
        } else if (finalText[i] === ' ') {
          display += ' ';
        } else {
          display += GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)];
        }
      }
      el.textContent = display;

      if (frame >= totalFrames) {
        clearInterval(timer);
        el.textContent = finalText;
        el.classList.remove('glitching');
      }
    }, 40);
  }

  // Fire on load, then every 8 seconds
  function fire() {
    var el = document.querySelector('.logo-main');
    if (!el) return;
    var text = 'Payload Obfuscation';
    scramble(el, text, 1200);
  }

  // Initial fire after short delay
  setTimeout(fire, 1800);
  // Repeat every 8 seconds
  setInterval(fire, 8000);
})();



// ═══════════════════════════════════════════════════════════════════════════
// ML LAB
// ═══════════════════════════════════════════════════════════════════════════

async function mlLoadComparison() {
  try {
    const r = await fetch('/api/ml/comparison');
    const d = await r.json();
    if (!d.success) { toast('Failed to load ML metrics'); return; }

    const cmp = d.comparison;
    const best = d.best_model;

    // Build comparison table
    const metrics = ['accuracy','precision','recall','f1_score','auc_roc','cv_mean','train_time_sec'];
    const labels  = ['Accuracy','Precision','Recall','F1 Score','AUC-ROC','CV Mean','Train Time'];

    let html = '<table class="tbl"><thead><tr><th>Model</th>';
    labels.forEach(l => { html += `<th>${l}</th>`; });
    html += '</tr></thead><tbody>';

    cmp.forEach(m => {
      const isBest = m.model_name === best;
      html += `<tr style="${isBest ? 'background:#1a1f36;border-left:3px solid #00e5ff' : ''}">`;
      html += `<td><strong>${m.model_name}</strong>${isBest ? ' <span style="color:#00e5ff;font-size:10px">BEST</span>' : ''}</td>`;
      html += `<td>${m.accuracy}%</td>`;
      html += `<td>${m.precision}%</td>`;
      html += `<td>${m.recall}%</td>`;
      html += `<td style="color:${m.f1_score > 90 ? '#69f0ae' : m.f1_score > 75 ? '#ff9100' : '#ff5252'}">${m.f1_score}%</td>`;
      html += `<td style="color:#00e5ff">${m.auc_roc}%</td>`;
      html += `<td>${m.cv_mean}% ± ${m.cv_std}%</td>`;
      html += `<td>${m.train_time_sec}s</td>`;
      html += '</tr>';
    });

    html += '</tbody></table>';
    document.getElementById('mlCompTable').innerHTML = html;
    document.getElementById('mlCompCard').style.display = 'block';

    // Dataset info
    const metricsResp = await fetch('/api/ml/metrics');
    const md = await metricsResp.json();
    if (md.success) {
      const ds = md.metrics.dataset || {};
      document.getElementById('mlDatasetInfo').innerHTML = `
        <div style="display:flex;gap:16px;flex-wrap:wrap">
          <div class="stat-box"><div class="stat-val">${ds.total_samples||'?'}</div><div class="stat-lbl">Total Samples</div></div>
          <div class="stat-box" style="color:#ff5252"><div class="stat-val">${ds.attack_samples||'?'}</div><div class="stat-lbl">Attack</div></div>
          <div class="stat-box" style="color:#69f0ae"><div class="stat-val">${ds.clean_samples||'?'}</div><div class="stat-lbl">Clean</div></div>
          <div class="stat-box"><div class="stat-val">${ds.train_size||'?'}</div><div class="stat-lbl">Train Split</div></div>
          <div class="stat-box"><div class="stat-val">${ds.test_size||'?'}</div><div class="stat-lbl">Test Split</div></div>
        </div>`;
      document.getElementById('mlDatasetCard').style.display = 'block';
    }

    toast('ML metrics loaded!');
  } catch(e) { toast('Error: ' + e.message); }
}

async function mlClassify() {
  const payload = document.getElementById('mlPayload').value.trim();
  if (!payload) { toast('Enter a payload'); return; }

  document.getElementById('mlClassifyResult').innerHTML = '<div class="sub">Classifying...</div>';

  try {
    const r = await fetch('/api/ml/classify', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({payload})
    });
    const d = await r.json();
    if (!d.success) { toast(d.message); return; }
    const res = d.result;

    const color = res.label === 'ATTACK' ? '#ff5252' : '#69f0ae';
    let votesHtml = Object.entries(res.model_votes || {}).map(([model, vote]) =>
      `<span style="color:${vote==='ATTACK'?'#ff5252':'#69f0ae'};margin-right:12px">
        <strong>${model}:</strong> ${vote}
      </span>`
    ).join('');

    document.getElementById('mlClassifyResult').innerHTML = `
      <div class="card" style="border-color:${color};margin-top:0">
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
          <div style="font-size:28px;font-weight:700;color:${color}">${res.label}</div>
          <div>
            <div style="color:#8892b0;font-size:12px">ENSEMBLE CONFIDENCE</div>
            <div style="font-size:18px;font-weight:600">${res.confidence}%</div>
          </div>
        </div>
        <div style="display:flex;gap:16px;margin-bottom:12px">
          <div class="stat-box" style="color:#ff5252"><div class="stat-val">${res.attack_probability}%</div><div class="stat-lbl">Attack Prob</div></div>
          <div class="stat-box" style="color:#69f0ae"><div class="stat-val">${res.clean_probability}%</div><div class="stat-lbl">Clean Prob</div></div>
        </div>
        <div style="margin-bottom:10px"><strong>Model Votes:</strong><br/>${votesHtml}</div>
        <div><strong>Features Detected:</strong>
          <div style="margin-top:6px">${(res.features_matched||[]).map(f=>
            `<span class="badge">${f}</span>`).join('')}
          </div>
        </div>
      </div>`;
  } catch(e) { toast('Error: ' + e.message); }
}

async function mlClassifyAll() {
  const payload = document.getElementById('mlPayload').value.trim();
  if (!payload) { toast('Enter a payload'); return; }

  const models = ['Logistic Regression', 'Random Forest', 'XGBoost'];
  let html = '<div style="margin-top:0">';

  for (const model of models) {
    try {
      const r = await fetch('/api/ml/model-classify', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({payload, model})
      });
      const d = await r.json();
      if (d.success) {
        const res = d.result;
        const color = res.label === 'ATTACK' ? '#ff5252' : '#69f0ae';
        html += `<div style="display:flex;justify-content:space-between;align-items:center;
                   padding:8px 12px;border:1px solid #1e2642;border-radius:6px;margin-bottom:6px">
          <strong>${res.model}</strong>
          <span style="color:${color};font-weight:700">${res.label}</span>
          <span style="color:#8892b0">Attack: ${res.attack_probability}%</span>
          <span style="color:#8892b0">Clean: ${res.clean_probability}%</span>
        </div>`;
      }
    } catch(e) {}
  }

  html += '</div>';
  document.getElementById('mlClassifyResult').innerHTML = html;
}

async function mlRetrainSynthetic() {
  if (!confirm('Retrain all models on 500 synthetic attack + 500 synthetic clean samples?')) return;
  toast('Retraining... this may take 10-30 seconds');
  document.getElementById('mlCompCard').style.display = 'none';

  try {
    const r = await fetch('/api/ml/retrain-synthetic', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({n_attack: 500, n_clean: 500})
    });
    const d = await r.json();
    if (!d.success) { toast('Retrain failed: ' + d.message); return; }
    toast('Retraining complete!');
    mlLoadComparison();
  } catch(e) { toast('Error: ' + e.message); }
}

async function researchFullTest() {
  const payload = document.getElementById('researchPayload').value.trim();
  const count = parseInt(document.getElementById('researchCount').value) || 15;
  if (!payload) { toast('Enter a payload'); return; }

  document.getElementById('researchResult').innerHTML = '<div class="sub">Running full research test across all 3 WAF engines...</div>';

  try {
    const r = await fetch('/api/research/full-test', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({payload, count})
    });
    const d = await r.json();
    if (!d.success) { toast(d.message); return; }

    const rw = d.regex_waf, crs = d.owasp_crs, ml = d.ml_ensemble;
    const barHtml = (bypassed, total) => {
      const pct = total > 0 ? (bypassed/total*100) : 0;
      const color = pct > 50 ? '#69f0ae' : pct > 20 ? '#ff9100' : '#ff5252';
      return `<div style="background:#0a0e1a;border-radius:4px;height:8px;width:100%;margin-top:4px">
        <div style="background:${color};width:${pct}%;height:8px;border-radius:4px"></div></div>`;
    };

    let detailsHtml = '<table class="tbl" style="margin-top:12px"><thead><tr><th>Technique</th><th>Regex WAF</th><th>OWASP CRS</th><th>ML Ensemble</th></tr></thead><tbody>';
    (d.variant_details || []).forEach(v => {
      const rS = v.regex_status === 'BYPASSED' ? '<span style="color:#69f0ae">BYPASSED</span>' : '<span style="color:#ff5252">BLOCKED</span>';
      const cS = v.crs_status === 'BYPASSED' ? '<span style="color:#69f0ae">BYPASSED</span>' : '<span style="color:#ff5252">BLOCKED</span>';
      const mS = v.ml_status === 'CLEAN' ? '<span style="color:#69f0ae">CLEAN</span>' : '<span style="color:#ff5252">ATTACK</span>';
      detailsHtml += `<tr><td style="font-size:11px">${v.technique}</td><td>${rS}</td><td>${cS}</td><td>${mS}</td></tr>`;
    });
    detailsHtml += '</tbody></table>';

    document.getElementById('researchResult').innerHTML = `
      <div class="card" style="margin-top:0">
        <h3 style="margin-bottom:14px">&#x1F3C1; Research Test Results — ${d.variant_count} variants</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:14px">
          <div class="card" style="margin:0;border-color:#7c4dff">
            <div style="color:#7c4dff;font-size:11px;font-weight:600;margin-bottom:6px">REGEX WAF</div>
            <div style="font-size:22px;font-weight:700;color:${rw.bypass_rate_pct>50?'#69f0ae':'#ff9100'}">${rw.bypass_rate_pct}%</div>
            <div style="color:#8892b0;font-size:11px">bypass rate</div>
            ${barHtml(rw.bypassed, rw.total)}
            <div style="color:#8892b0;font-size:11px;margin-top:4px">${rw.bypassed}/${rw.total} bypassed</div>
          </div>
          <div class="card" style="margin:0;border-color:#00e5ff">
            <div style="color:#00e5ff;font-size:11px;font-weight:600;margin-bottom:6px">OWASP CRS</div>
            <div style="font-size:22px;font-weight:700;color:${crs.bypass_rate_pct>50?'#69f0ae':'#ff9100'}">${crs.bypass_rate_pct}%</div>
            <div style="color:#8892b0;font-size:11px">bypass rate</div>
            ${barHtml(crs.bypassed, crs.total)}
            <div style="color:#8892b0;font-size:11px;margin-top:4px">${crs.bypassed}/${crs.total} bypassed</div>
          </div>
          <div class="card" style="margin:0;border-color:#69f0ae">
            <div style="color:#69f0ae;font-size:11px;font-weight:600;margin-bottom:6px">ML ENSEMBLE</div>
            <div style="font-size:22px;font-weight:700;color:${ml.bypass_rate_pct>50?'#69f0ae':'#ff9100'}">${ml.bypass_rate_pct}%</div>
            <div style="color:#8892b0;font-size:11px">evasion rate</div>
            ${barHtml(ml.bypassed, ml.total)}
            <div style="color:#8892b0;font-size:11px;margin-top:4px">${ml.bypassed}/${ml.total} evaded</div>
          </div>
        </div>
        ${detailsHtml}
      </div>`;
  } catch(e) { toast('Error: ' + e.message); }
}


// ═══════════════════════════════════════════════════════════════════════════
// METRICS
// ═══════════════════════════════════════════════════════════════════════════

async function metricsLoad() {
  try {
    const [sResp, rResp, rkResp, sysResp] = await Promise.all([
      fetch('/api/metrics/summary'),
      fetch('/api/metrics/recent?n=20'),
      fetch('/api/metrics/technique-ranking'),
      fetch('/api/metrics/system'),
    ]);

    const summary = (await sResp.json()).summary || {};
    const recent = (await rResp.json()).records || [];
    const ranking = (await rkResp.json()).ranking || [];
    const sys = (await sysResp.json()).system || {};

    // Summary
    document.getElementById('metricsSummary').innerHTML = `
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <div class="stat-box"><div class="stat-val">${summary.total_requests||0}</div><div class="stat-lbl">Total Requests</div></div>
        <div class="stat-box" style="color:#69f0ae"><div class="stat-val">${summary.bypass_rate_pct||0}%</div><div class="stat-lbl">Bypass Rate</div></div>
        <div class="stat-box" style="color:#ff5252"><div class="stat-val">${summary.detection_rate_pct||0}%</div><div class="stat-lbl">Detection Rate</div></div>
        <div class="stat-box"><div class="stat-val">${summary.avg_response_time_ms||0}ms</div><div class="stat-lbl">Avg Response</div></div>
        <div class="stat-box"><div class="stat-val">${summary.p95_response_time_ms||0}ms</div><div class="stat-lbl">P95 Response</div></div>
        <div class="stat-box"><div class="stat-val">${summary.avg_payload_size_bytes||0}B</div><div class="stat-lbl">Avg Payload Size</div></div>
        <div class="stat-box"><div class="stat-val">${summary.max_payload_size_bytes||0}B</div><div class="stat-lbl">Max Payload Size</div></div>
        <div class="stat-box"><div class="stat-val">${summary.avg_cpu_percent||0}%</div><div class="stat-lbl">Avg CPU</div></div>
      </div>
      <div style="margin-top:12px">
        <div style="color:#8892b0;font-size:11px;margin-bottom:6px">PAYLOAD SIZE DISTRIBUTION</div>
        <div style="display:flex;gap:8px">
          ${Object.entries(summary.size_buckets||{}).map(([k,v]) =>
            `<span style="background:#12172b;border:1px solid #1e2642;border-radius:4px;padding:4px 8px;font-size:11px">
              ${k}: <strong>${v}</strong>
            </span>`).join('')}
        </div>
      </div>`;

    // Technique ranking
    if (ranking.length > 0) {
      let rkHtml = '';
      ranking.forEach((t, i) => {
        const pct = t.bypass_rate_pct;
        const color = pct > 70 ? '#69f0ae' : pct > 40 ? '#ff9100' : '#ff5252';
        rkHtml += `<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;padding:6px 10px;background:#12172b;border-radius:4px">
          <span style="color:#8892b0;width:20px;text-align:right">#${i+1}</span>
          <span style="flex:1;font-size:12px">${t.technique||'(unknown)'}</span>
          <span style="color:${color};font-weight:600;width:40px;text-align:right">${pct}%</span>
          <span style="color:#8892b0;font-size:11px">${t.bypassed}/${t.total}</span>
        </div>`;
      });
      document.getElementById('metricsRanking').innerHTML = rkHtml;
    } else {
      document.getElementById('metricsRanking').innerHTML = '<div class="sub">No techniques recorded yet. Run a batch test first.</div>';
    }

    // Recent records
    if (recent.length > 0) {
      let recHtml = '<table class="tbl"><thead><tr><th>Technique</th><th>Status</th><th>Size</th><th>Time</th><th>CPU</th></tr></thead><tbody>';
      recent.forEach(r => {
        const sc = r.status === 'BYPASSED' ? '#69f0ae' : '#ff5252';
        recHtml += `<tr>
          <td style="font-size:11px">${r.technique||''}</td>
          <td style="color:${sc};font-weight:600">${r.status}</td>
          <td>${r.payload_size_bytes}B</td>
          <td>${r.response_time_ms}ms</td>
          <td>${r.cpu_percent}%</td>
        </tr>`;
      });
      recHtml += '</tbody></table>';
      document.getElementById('metricsRecent').innerHTML = recHtml;
    } else {
      document.getElementById('metricsRecent').innerHTML = '<div class="sub">No recent requests recorded.</div>';
    }

    // System info
    document.getElementById('metricsSystem').innerHTML = `
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <div class="stat-box" style="color:${sys.psutil_available?'#69f0ae':'#ff9100'}">
          <div class="stat-val">${sys.psutil_available ? 'YES' : 'NO'}</div>
          <div class="stat-lbl">psutil Active</div>
        </div>
        ${sys.cpu_count ? `<div class="stat-box"><div class="stat-val">${sys.cpu_count}</div><div class="stat-lbl">CPU Cores</div></div>` : ''}
        ${sys.total_memory_gb ? `<div class="stat-box"><div class="stat-val">${sys.total_memory_gb}GB</div><div class="stat-lbl">Total RAM</div></div>` : ''}
        <div class="stat-box"><div class="stat-val">${sys.records_in_window||0}</div><div class="stat-lbl">Records Stored</div></div>
      </div>`;

    toast('Metrics refreshed!');
  } catch(e) { toast('Error: ' + e.message); }
}

async function metricsClear() {
  if (!confirm('Clear all recorded metrics?')) return;
  try {
    await fetch('/api/metrics/clear', {method:'POST'});
    toast('Metrics cleared');
    metricsLoad();
  } catch(e) { toast('Error: ' + e.message); }
}


// ═══════════════════════════════════════════════════════════════════════════
// CRS ENGINE
// ═══════════════════════════════════════════════════════════════════════════

function crsModeChanged() {
  const mode = document.getElementById('crsMode').value;
  document.getElementById('crsLiveConfig').style.display = mode === 'live' ? 'block' : 'none';
}

async function crsApplyMode() {
  const mode = document.getElementById('crsMode').value;
  const url = document.getElementById('crsUrl').value || 'http://localhost:8080';
  const paranoia = parseInt(document.getElementById('crsParanoia').value) || 1;

  try {
    const r = await fetch('/api/modsec/set-mode', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({mode, base_url: url, paranoia_level: paranoia})
    });
    const d = await r.json();
    toast(d.success ? `CRS mode: ${d.mode} | Paranoia: ${d.paranoia_level}` : 'Failed to apply mode');
  } catch(e) { toast('Error: ' + e.message); }
}

async function crsLoadRules() {
  try {
    const r = await fetch('/api/modsec/rules');
    const d = await r.json();
    if (!d.success) { toast('Failed to load rules'); return; }

    const rules = d.rules || [];
    const byCategory = {};
    rules.forEach(r => {
      if (!byCategory[r.category]) byCategory[r.category] = [];
      byCategory[r.category].push(r);
    });

    let html = `<div class="sub" style="margin-bottom:10px">Mode: <strong>${d.mode}</strong> | Paranoia: <strong>${d.paranoia_level}</strong> | Rules loaded: <strong>${rules.length}</strong></div>`;

    Object.entries(byCategory).forEach(([cat, catRules]) => {
      html += `<div style="margin-bottom:6px;color:#00e5ff;font-size:11px;font-weight:600">${cat.toUpperCase()}</div>`;
      catRules.forEach(r => {
        const sevColor = r.severity === 'CRITICAL' ? '#ff5252' : r.severity === 'WARNING' ? '#ff9100' : '#8892b0';
        html += `<div style="display:flex;align-items:center;gap:10px;padding:5px 10px;background:#12172b;border-radius:4px;margin-bottom:3px;font-size:11px">
          <span style="color:#8892b0;width:60px">${r.id}</span>
          <span style="flex:1">${r.name.substring(0,60)}${r.name.length>60?'...':''}</span>
          <span style="color:${sevColor};width:60px;text-align:right">${r.severity}</span>
          <span style="color:#8892b0;width:30px;text-align:right">${r.pattern_count}p</span>
        </div>`;
      });
    });

    document.getElementById('crsRulesList').innerHTML = html;
    toast(`${rules.length} CRS rules loaded`);
  } catch(e) { toast('Error: ' + e.message); }
}

async function crsBatchTest() {
  const payload = document.getElementById('crsPayload').value.trim();
  const count = parseInt(document.getElementById('crsCount').value) || 20;
  if (!payload) { toast('Enter a payload'); return; }

  document.getElementById('crsBatchOut').style.display = 'none';
  document.getElementById('crsSummary').innerHTML = '<div class="sub">Testing...</div>';

  try {
    const r = await fetch('/api/modsec/batch-test', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({payload, count})
    });
    const d = await r.json();
    if (!d.success) { toast(d.message); return; }

    const rep = d.report;
    const bypassColor = rep.bypass_rate_pct > 50 ? '#69f0ae' : rep.bypass_rate_pct > 20 ? '#ff9100' : '#ff5252';

    document.getElementById('crsSummary').innerHTML = `
      <div style="display:flex;gap:16px;flex-wrap:wrap">
        <div class="stat-box"><div class="stat-val">${rep.total_tested}</div><div class="stat-lbl">Tested</div></div>
        <div class="stat-box" style="color:#ff5252"><div class="stat-val">${rep.blocked}</div><div class="stat-lbl">Blocked</div></div>
        <div class="stat-box" style="color:${bypassColor}"><div class="stat-val">${rep.bypassed}</div><div class="stat-lbl">Bypassed</div></div>
        <div class="stat-box" style="color:${bypassColor}"><div class="stat-val">${rep.bypass_rate_pct}%</div><div class="stat-lbl">Bypass Rate</div></div>
      </div>
      <div style="background:#0a0e1a;border-radius:6px;height:10px;margin-top:12px">
        <div style="background:${bypassColor};width:${rep.bypass_rate_pct}%;height:10px;border-radius:6px;transition:width 0.6s"></div>
      </div>`;

    // Results table
    let resHtml = '<table class="tbl"><thead><tr><th>#</th><th>Status</th><th>Technique</th><th>Rules Matched</th><th>Time</th></tr></thead><tbody>';
    (rep.results || []).forEach((r, i) => {
      const sc = r.blocked ? '#ff5252' : '#69f0ae';
      const tech = (d.technique_map || {})[r.payload_preview] || '';
      const rules = (r.matched_rules || []).map(mr => mr.category).join(', ') || '—';
      resHtml += `<tr>
        <td>${i+1}</td>
        <td style="color:${sc};font-weight:600">${r.status}</td>
        <td style="font-size:11px">${tech}</td>
        <td style="color:#8892b0;font-size:11px">${rules}</td>
        <td>${r.response_time_ms}ms</td>
      </tr>`;
    });
    resHtml += '</tbody></table>';
    document.getElementById('crsResults').innerHTML = resHtml;
    document.getElementById('crsBatchOut').style.display = 'block';

    toast(`CRS test done — ${rep.bypass_rate_pct}% bypass rate`);
  } catch(e) { toast('Error: ' + e.message); }
}

async function crsSingleInspect() {
  const payload = document.getElementById('crsSinglePayload').value.trim();
  if (!payload) { toast('Enter a payload'); return; }

  try {
    const r = await fetch('/api/modsec/inspect', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({payload})
    });
    const d = await r.json();
    if (!d.success) { toast(d.message); return; }

    const res = d.result;
    const color = res.blocked ? '#ff5252' : '#69f0ae';
    let rulesHtml = '';
    if (res.matched_rules && res.matched_rules.length > 0) {
      rulesHtml = '<div style="margin-top:10px"><strong>Matched Rules:</strong>';
      res.matched_rules.forEach(mr => {
        const sevColor = mr.severity === 'CRITICAL' ? '#ff5252' : '#ff9100';
        rulesHtml += `<div style="display:flex;gap:10px;padding:4px 0;font-size:11px;border-bottom:1px solid #1e2642">
          <span style="color:#8892b0">${mr.rule_id}</span>
          <span style="flex:1">${mr.rule_name}</span>
          <span style="color:${sevColor}">${mr.severity}</span>
        </div>`;
      });
      rulesHtml += '</div>';
    }

    document.getElementById('crsSingleResult').innerHTML = `
      <div class="card" style="margin:0;border-color:${color}">
        <div style="font-size:20px;font-weight:700;color:${color}">${res.status}</div>
        <div style="color:#8892b0;font-size:11px">HTTP ${res.status_code} | ${res.response_time_ms}ms | Mode: ${res.mode}</div>
        ${rulesHtml || '<div class="sub" style="margin-top:8px">No CRS rules matched</div>'}
      </div>`;
  } catch(e) { toast('Error: ' + e.message); }
}

// Add .stat-box styles if not present
(function addStatBoxStyles() {
  if (document.getElementById('stat-box-style')) return;
  const style = document.createElement('style');
  style.id = 'stat-box-style';
  style.textContent = `
    .stat-box {
      background: #12172b;
      border: 1px solid #1e2642;
      border-radius: 10px;
      padding: 12px 18px;
      text-align: center;
      min-width: 80px;
    }
    .stat-val {
      font-size: 22px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }
    .stat-lbl {
      font-size: 10px;
      text-transform: uppercase;
      color: #8892b0;
      margin-top: 2px;
      letter-spacing: 0.05em;
    }
    .badge {
      display: inline-block;
      background: #1a1f36;
      border: 1px solid #7c4dff;
      border-radius: 4px;
      padding: 2px 8px;
      font-size: 11px;
      color: #7c4dff;
      margin: 2px 4px 2px 0;
    }
  `;
  document.head.appendChild(style);
})();


// ═══════════════════════════════════════════════════════════════════════════
// DATASET TAB — UNSW-NB15 Upload & Background Training
// ═══════════════════════════════════════════════════════════════════════════

let _datasetUploadedPath = null;
let _datasetTrainJobId = null;
let _datasetTrainPoller = null;

async function datasetUpload() {
  const fileInput = document.getElementById('datasetFile');
  if (!fileInput.files || !fileInput.files[0]) {
    toast('Select a CSV file first'); return;
  }

  const file = fileInput.files[0];
  const sizeMB = (file.size / 1024 / 1024).toFixed(1);

  document.getElementById('datasetUploadProgress').style.display = 'block';
  document.getElementById('datasetUploadBar').style.width = '0%';
  document.getElementById('datasetUploadMsg').textContent = `Uploading ${sizeMB} MB…`;
  document.getElementById('datasetFileInfoCard').style.display = 'none';

  const formData = new FormData();
  formData.append('file', file);

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/dataset/upload-unswnb15', true);

  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const pct = Math.round(e.loaded / e.total * 100);
      document.getElementById('datasetUploadBar').style.width = pct + '%';
      document.getElementById('datasetUploadMsg').textContent =
        `Uploading… ${(e.loaded/1024/1024).toFixed(1)} / ${(e.total/1024/1024).toFixed(1)} MB (${pct}%)`;
    }
  };

  xhr.onload = () => {
    try {
      const d = JSON.parse(xhr.responseText);
      if (d.success) {
        document.getElementById('datasetUploadBar').style.width = '100%';
        document.getElementById('datasetUploadMsg').textContent = `Upload complete — ${d.size_mb} MB saved`;
        _datasetUploadedPath = d.path;
        datasetShowFileInfo(d);
        toast(`File uploaded: ${d.filename}`);
      } else {
        document.getElementById('datasetUploadMsg').textContent = 'Upload failed: ' + d.message;
        toast('Upload failed: ' + d.message);
      }
    } catch(e) {
      document.getElementById('datasetUploadMsg').textContent = 'Server error';
    }
  };

  xhr.onerror = () => {
    document.getElementById('datasetUploadMsg').textContent = 'Network error during upload';
    toast('Network error');
  };

  xhr.send(formData);
}

function datasetShowFileInfo(d) {
  const cols = d.columns || [];
  const labelColDetected = d.detected_label_col || 'label';
  document.getElementById('datasetLabelCol').value = labelColDetected;

  const rowsEst = d.row_count_est ? d.row_count_est.toLocaleString() : '?';
  const colList = cols.slice(0, 20).join(', ') + (cols.length > 20 ? `… (+${cols.length - 20} more)` : '');

  document.getElementById('datasetFileInfo').innerHTML = `
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px">
      <div class="stat-box"><div class="stat-val">${d.size_mb} MB</div><div class="stat-lbl">File Size</div></div>
      <div class="stat-box"><div class="stat-val">${rowsEst}</div><div class="stat-lbl">Rows (est.)</div></div>
      <div class="stat-box"><div class="stat-val">${cols.length}</div><div class="stat-lbl">Columns</div></div>
      <div class="stat-box" style="color:#00e5ff"><div class="stat-val">${labelColDetected}</div><div class="stat-lbl">Label Col</div></div>
    </div>
    <div style="font-size:11px;color:#8892b0;margin-bottom:4px">COLUMNS</div>
    <div style="font-size:11px;background:#0a0e1a;padding:8px;border-radius:4px;color:#ccd6f6;word-break:break-all">${colList}</div>
  `;
  document.getElementById('datasetFileInfoCard').style.display = 'block';
}

async function datasetStartTrain() {
  if (!_datasetUploadedPath) { toast('Upload a file first'); return; }

  const labelCol = document.getElementById('datasetLabelCol').value.trim() || 'label';
  const maxSamples = parseInt(document.getElementById('datasetMaxSamples').value) || 200000;

  if (!confirm(`Start background training on up to ${maxSamples.toLocaleString()} rows?\nThis runs in the background — you can keep using the app.`)) return;

  try {
    const r = await fetch('/api/dataset/retrain-unswnb15-start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        path: _datasetUploadedPath,
        label_col: labelCol,
        max_samples: maxSamples,
        chunk_size: 50000,
      })
    });
    const d = await r.json();
    if (!d.success) { toast(d.message); return; }

    _datasetTrainJobId = d.job_id;
    document.getElementById('datasetTrainCard').style.display = 'block';
    document.getElementById('datasetTrainStatus').innerHTML = '<span style="color:#ff9100">QUEUED</span>';
    document.getElementById('datasetTrainBar').style.width = '0%';
    document.getElementById('datasetTrainMsg').textContent = 'Job queued…';
    toast('Training started in background!');

    // Start polling
    if (_datasetTrainPoller) clearInterval(_datasetTrainPoller);
    _datasetTrainPoller = setInterval(datasetPollJob, 2000);

  } catch(e) { toast('Error: ' + e.message); }
}

async function datasetPollJob() {
  if (!_datasetTrainJobId) { clearInterval(_datasetTrainPoller); return; }

  try {
    const r = await fetch(`/api/dataset/train-job/${_datasetTrainJobId}`);
    const d = await r.json();
    if (!d.success) { clearInterval(_datasetTrainPoller); return; }

    const job = d.job;
    const statusColors = {
      queued: '#ff9100', loading: '#00e5ff', preprocessing: '#7c4dff',
      training: '#7c4dff', done: '#69f0ae', error: '#ff5252'
    };
    const color = statusColors[job.status] || '#8892b0';

    document.getElementById('datasetTrainStatus').innerHTML =
      `<span style="color:${color};font-weight:700;text-transform:uppercase">${job.status}</span>
       ${job.rows_read > 0 ? `<span style="color:#8892b0;font-size:12px;margin-left:10px">
         ${job.rows_read.toLocaleString()} rows read</span>` : ''}`;
    document.getElementById('datasetTrainBar').style.width = job.progress + '%';
    document.getElementById('datasetTrainBar').style.background = color;
    document.getElementById('datasetTrainMsg').textContent = job.message;

    if (job.status === 'done') {
      clearInterval(_datasetTrainPoller);
      toast('Training complete!');
      datasetShowTrainResult(job.result);
    } else if (job.status === 'error') {
      clearInterval(_datasetTrainPoller);
      toast('Training error: ' + job.message);
    }
  } catch(e) {
    // Network blip — keep polling
  }
}

function datasetShowTrainResult(result) {
  if (!result) return;
  const b = result.balance || {};
  const metrics = result.metrics || {};

  let metricsHtml = '';
  if (metrics.models) {
    metricsHtml = '<div style="margin-top:12px"><strong>Model Metrics</strong><table class="tbl" style="margin-top:8px"><thead><tr><th>Model</th><th>Accuracy</th><th>F1</th><th>AUC</th></tr></thead><tbody>';
    metrics.models.forEach(m => {
      metricsHtml += `<tr><td>${m.model_name}</td><td>${m.accuracy}%</td><td>${m.f1_score}%</td><td>${m.auc_roc}%</td></tr>`;
    });
    metricsHtml += '</tbody></table></div>';
  }

  document.getElementById('datasetResultContent').innerHTML = `
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px">
      <div class="stat-box"><div class="stat-val">${result.samples ? result.samples.toLocaleString() : '?'}</div><div class="stat-lbl">Samples Trained</div></div>
      <div class="stat-box" style="color:#ff5252"><div class="stat-val">${b.attack || 0}</div><div class="stat-lbl">Attack</div></div>
      <div class="stat-box" style="color:#69f0ae"><div class="stat-val">${b.clean || 0}</div><div class="stat-lbl">Clean</div></div>
      <div class="stat-box" style="color:${b.balanced ? '#69f0ae' : '#ff9100'}">
        <div class="stat-val">${b.balanced ? 'YES' : 'NO'}</div><div class="stat-lbl">Balanced</div>
      </div>
    </div>
    ${metricsHtml}
    <div class="sub" style="margin-top:10px">Switch to ML Lab tab to run classifications with the new models.</div>
  `;
  document.getElementById('datasetResultCard').style.display = 'block';
}

async function datasetListFiles() {
  try {
    const r = await fetch('/api/dataset/uploaded-files');
    const d = await r.json();
    const files = d.files || [];

    if (files.length === 0) {
      document.getElementById('datasetFileList').innerHTML = '<div class="sub">No uploaded files yet.</div>';
      return;
    }

    let html = '';
    files.forEach(f => {
      html += `<div style="display:flex;align-items:center;gap:10px;padding:8px 10px;background:#12172b;border-radius:6px;margin-bottom:6px">
        <span style="flex:1;font-size:12px">${f.filename}</span>
        <span style="color:#8892b0;font-size:11px">${f.size_mb} MB</span>
        <button class="btn btn-o" style="padding:4px 10px;font-size:11px"
          onclick="_datasetUploadedPath='${f.path}';datasetProbeExisting('${f.path}');toast('File selected')">Use</button>
        <button class="btn" style="padding:4px 10px;font-size:11px;color:#ff5252;border-color:#ff5252"
          onclick="datasetDeleteFile('${f.path}')">Delete</button>
      </div>`;
    });
    document.getElementById('datasetFileList').innerHTML = html;
  } catch(e) { toast('Error: ' + e.message); }
}

async function datasetProbeExisting(path) {
  try {
    const r = await fetch('/api/dataset/probe-unswnb15', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path})
    });
    const d = await r.json();
    if (d.success && d.info) {
      const info = d.info;
      datasetShowFileInfo({
        size_mb: info.size_mb,
        row_count_est: info.row_count_est,
        columns: info.columns,
        detected_label_col: info.detected_label_col,
        filename: path.split('/').pop(),
      });
    }
  } catch(e) {}
}

async function datasetDeleteFile(path) {
  if (!confirm('Delete this uploaded file?')) return;
  try {
    const r = await fetch('/api/dataset/delete-file', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path})
    });
    const d = await r.json();
    toast(d.success ? 'File deleted' : d.message);
    datasetListFiles();
  } catch(e) { toast('Error: ' + e.message); }
}
