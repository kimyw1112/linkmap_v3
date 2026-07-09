'use strict';
/* ═══ STORAGE ════════════════════════════════════════════════════ */
const SESSION_KEY = 'lm_session';
let user = null;
let D = { people:[], nid:1 };
const storeKey = () => `lm_data_${user.emp}`;
const pinKey   = () => `lm_pin_${user.emp}`;
const encKeyId = () => `lm_ek_${user.emp}`;   // 암호화 키 저장 키

/* ═══ 레이어2 — AES-GCM 암호화 저장 ════════════════════════════
   Web Crypto API (브라우저 내장, 서버 불필요)
   - AES-GCM 256bit : 군사급 대칭키 암호화
   - 기기마다 고유 키 생성 → 다른 기기에서 복사해도 복호화 불가
   - 개발자도구 localStorage 탭에서 암호문만 보임
   ⚠ 키도 같은 브라우저에 저장되므로 PIN 잠금(레이어6)과 함께 써야 최강
════════════════════════════════════════════════════════════════ */

/* 암호화 키 불러오기 or 최초 생성 */
async function getEncKey(){
  try{
    const stored=localStorage.getItem(encKeyId());
    if(stored){
      const raw=Uint8Array.from(atob(stored),c=>c.charCodeAt(0));
      return await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
    }
  }catch(e){}
  /* 처음 실행 — 256bit 키 생성 */
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
  const exported=await crypto.subtle.exportKey('raw',key);
  localStorage.setItem(encKeyId(),btoa(String.fromCharCode(...new Uint8Array(exported))));
  return key;
}

/* 평문 JSON → 암호문 Base64 저장 */
async function saveEncrypted(storageKey,data){
  try{
    const key=await getEncKey();
    const iv=crypto.getRandomValues(new Uint8Array(12));          // 96bit IV (매번 새로)
    const enc=await crypto.subtle.encrypt(
      {name:'AES-GCM',iv},key,new TextEncoder().encode(JSON.stringify(data))
    );
    localStorage.setItem(storageKey,JSON.stringify({
      v:1,
      iv:btoa(String.fromCharCode(...iv)),
      ct:btoa(String.fromCharCode(...new Uint8Array(enc))),
    }));
  }catch(e){ console.warn('암호화 저장 실패',e); }
}

/* 암호문 Base64 → 평문 JSON 복원 */
async function loadDecrypted(storageKey){
  try{
    const raw=localStorage.getItem(storageKey); if(!raw) return null;
    const {v,iv,ct}=JSON.parse(raw);
    /* v가 없으면 구버전 평문 → 그대로 파싱 후 재암호화 */
    if(!v){
      const plain=JSON.parse(raw);
      return plain;
    }
    const key=await getEncKey();
    const dec=await crypto.subtle.decrypt(
      {name:'AES-GCM',iv:Uint8Array.from(atob(iv),c=>c.charCodeAt(0))},
      key,
      Uint8Array.from(atob(ct),c=>c.charCodeAt(0))
    );
    return JSON.parse(new TextDecoder().decode(dec));
  }catch(e){ return null; }
}

/* save / load — 비동기 래퍼 */
function save(){
  saveEncrypted(storeKey(),D).catch(()=>{
    /* 암호화 실패 시 평문으로 fallback (서비스 중단 방지) */
    try{ localStorage.setItem(storeKey(),JSON.stringify(D)); }catch(e){ toast('저장 실패','⚠'); }
  });
}
function load(){
  /* 비동기지만 init()에서 await으로 호출 */
  return loadDecrypted(storeKey()).then(r=>{
    if(r){ D=r; }
    D.people=D.people||[]; D.nid=D.nid||1;
    /* 구버전 rel(customer/friend/prospect) → 신규 그룹 키로 정규화 */
    D.people.forEach(p=>{ p.rel = normalizeRel(p.rel); });
    /* nid 무결성: 기존 인맥 최대 id보다 작으면 보정 (id 충돌 방지) */
    const maxId = D.people.reduce((m,p)=>Math.max(m, p.id||0), 0);
    if(D.nid <= maxId) D.nid = maxId + 1;
    /* 구버전 평문 데이터가 있으면 즉시 재암호화 */
    const raw=localStorage.getItem(storeKey());
    if(raw){ try{ const t=JSON.parse(raw); if(!t.v) save(); }catch(e){} }
  });
}

/* 일정 저장도 암호화 */
function saveScheds(){
  saveEncrypted(`lm_sched_${user.emp}`,SCHEDS).catch(()=>{
    try{ localStorage.setItem(`lm_sched_${user.emp}`,JSON.stringify(SCHEDS)); }catch(e){}
  });
}
function loadScheds(){
  return loadDecrypted(`lm_sched_${user.emp}`).then(r=>{
    SCHEDS=Array.isArray(r)?r:[];
  });
}

/* ═══ 상수 ═══════════════════════════════════════════════════════ */
const REL = {
  alumni: { lbl:'동창',       col:'#1A6FD4', sh:'동창' },
  work:   { lbl:'직장 지인',  col:'#15803D', sh:'직장' },
  family: { lbl:'가족·친척',  col:'#DC2626', sh:'가족' },
  etc:    { lbl:'기타',       col:'#9333EA', sh:'기타' },
};
/* 구버전 데이터(customer/friend/prospect) → 신규 그룹 매핑 */
const REL_MIGRATE = { customer:'alumni', friend:'work', prospect:'etc' };
function normalizeRel(r){
  if(REL[r]) return r;               // 이미 신규 키면 그대로
  return REL_MIGRATE[r] || 'etc';    // 구버전이면 매핑, 없으면 기타
}
/* 사람의 그룹 표시명: 기타면 사용자 지정 그룹명(있으면), 나머지는 그룹 라벨 */
function groupNameOf(p){
  const r = normalizeRel(p.rel);
  if(r==='etc' && p.group) return p.group;
  return REL[r].lbl;
}
/* ═══ 파이프라인 ══════════════════════════════════════════════════
   4단계 영업 파이프라인 — 상세 시트 내 체크리스트 + 타임라인
   person.pipeline = { stage:-1~3, dates:[null|'YYYY-MM-DD'×4], history:[] }
════════════════════════════════════════════════════════════════ */
const PIPELINE_STAGES = [
  { label:'고객등록', icon:'👤', col:'#15803D', bg:'#ECFDF5',
    script:'안녕하세요! 오늘 고객님 정보를 정리했습니다. 앞으로 잘 부탁드립니다 😊 혹시 보장 내용 관련해서 궁금한 점이 생기시면 편하게 연락 주세요.' },
  { label:'보장분석', icon:'🔍', col:'#D97706', bg:'#FFFBEB',
    script:'고객님, 현재 갖고 계신 보장 내용을 같이 정리해 드리려고 합니다. 10분 정도 시간 내주시면 지금 어떤 보장이 있고, 부족한 부분이 뭔지 한눈에 확인하실 수 있습니다.' },
  { label:'가입설계', icon:'📋', col:'#1A6FD4', bg:'#EFF6FF',
    script:'고객님 상황에 딱 맞는 설계를 준비했습니다. 부담 없이 한번 같이 살펴보시겠어요? 가입하지 않으셔도 되니 편하게 보시면서 궁금한 점 물어봐 주세요.' },
  { label:'보험가입', icon:'✅', col:'#9333EA', bg:'#F5F3FF',
    script:'가입해 주셔서 진심으로 감사합니다! 앞으로도 보장 잘 챙겨드릴게요 😊 주변에 보험 고민하시는 분 계시면 편하게 소개해 주시면 감사하겠습니다.' },
];

function ensurePipeline(p){
  if(!p.pipeline) p.pipeline={ stage:-1, dates:[null,null,null,null], history:[] };
  if(!p.pipeline.dates||p.pipeline.dates.length<4)
    p.pipeline.dates=Array(4).fill(null).map((_,i)=>(p.pipeline.dates||[])[i]||null);
  if(!p.pipeline.history) p.pipeline.history=[];
  return p.pipeline;
}

function toggleStage(personId,stageIdx){
  const p=D.people.find(x=>x.id===personId); if(!p) return;
  const pl=ensurePipeline(p);
  const today=toDateStr(new Date());
  const wasChecked=pl.dates[stageIdx]!==null;
  if(wasChecked){
    for(let i=stageIdx;i<4;i++) pl.dates[i]=null;
    pl.stage=stageIdx-1;
    pl.history.push({date:today,action:'uncheck',stage:stageIdx});
    toast(PIPELINE_STAGES[stageIdx].label+' 단계 해제','↩');
  } else {
    for(let i=0;i<=stageIdx;i++) if(!pl.dates[i]) pl.dates[i]=today;
    pl.stage=stageIdx;
    pl.history.push({date:today,action:'check',stage:stageIdx});
    toast(PIPELINE_STAGES[stageIdx].icon+' '+PIPELINE_STAGES[stageIdx].label+' 완료!','✅');
    /* 보험가입(3단계=마지막) 완료 → 소개자 감사 일정 자동 생성 */
    if(stageIdx===3 && p.ref){
      const refP=D.people.find(x=>x.id===p.ref);
      if(refP){
        const thanksTitle=`[감사 연락] ${refP.name}님께 — ${p.name} 가입 완료`;
        const alreadyExists=SCHEDS.some(s=>s.personId===refP.id&&s.title===thanksTitle);
        if(!alreadyExists){
          SCHEDS.push({
            id:newSchedId(), date:today, time:'',
            title:thanksTitle, personId:refP.id,
            memo:`${p.name}님이 보험가입을 완료했습니다. ${refP.name}님께 감사 연락을 드리세요 🙏`,
            autoGenerated:true,
            isMeeting:false,   // 감사 연락은 비대면
          });
          saveScheds();
          setTimeout(()=>toast(`📅 ${refP.name}님께 감사 연락 일정이 자동 생성됐습니다`,'🙏'),1200);
        }
      }
    }
    if(stageIdx===3) setTimeout(()=>toast(p.name+'님 보험가입 완료! 이제 소개 요청을 진행해보세요 🎉','🎊'),800);
  }
  save(); refresh(); openDetail(personId);
}

function renderPipelineHTML(p){
  const pl=ensurePipeline(p);
  const completedCount=pl.dates.filter(d=>d!==null).length;
  const pct=Math.round(completedCount/4*100);

  const stageRows=PIPELINE_STAGES.map((st,i)=>{
    const done  =pl.dates[i]!==null;
    const active=!done&&(i===0||pl.dates[i-1]!==null);
    const locked=!done&&!active;
    const dateStr=pl.dates[i]?`<span class="pl-date">${pl.dates[i]}</span>`:'';
    const stateClass=done?'done':active?'active':'locked';
    const checkIcon=done?'✓':active?'→':'';
    return `<div class="pl-row ${stateClass}" onclick="${locked?'':('toggleStage('+p.id+','+i+')')}" style="cursor:${locked?'default':'pointer'}">
      <div class="pl-check ${stateClass}" style="${done?'background:'+st.col+';color:#fff;border-color:'+st.col:''}">
        ${checkIcon}
      </div>
      <div class="pl-info">
        <span class="pl-icon">${st.icon}</span>
        <span class="pl-label" style="${done?'color:'+st.col:''}">
          ${esc(st.label)}${active&&!done?' <span class="pl-now">진행 중</span>':''}
        </span>
      </div>
      ${dateStr}
    </div>`;
  }).join('');

  let histHTML='';
  if(pl.history&&pl.history.length>0){
    const recent=[...pl.history].reverse().slice(0,5);
    histHTML=`<div class="pl-history">
      <div class="pl-hist-title">⏱ 진행 히스토리</div>
      ${recent.map(h=>{
        const st=PIPELINE_STAGES[h.stage];
        const isCheck=h.action==='check';
        return `<div class="pl-hist-row">
          <div class="pl-hist-dot" style="background:${isCheck?st.col:'#9C8878'}"></div>
          <div class="pl-hist-body">
            <span class="pl-hist-action" style="color:${isCheck?st.col:'#9C8878'}">${isCheck?'완료':'해제'}</span>
            <span class="pl-hist-stage">${st.icon} ${esc(st.label)}</span>
            <span class="pl-hist-date">${h.date}</span>
          </div>
        </div>`;
      }).join('')}
    </div>`;
  }

  /* ── 현재 단계 스크립트 ── */
  const curStageIdx = pl.dates.filter(Boolean).length - 1;
  let pipelineScriptHTML = '';
  if(curStageIdx >= 0 && curStageIdx < PIPELINE_STAGES.length){
    const cst = PIPELINE_STAGES[curStageIdx];
    pipelineScriptHTML = `<div class="pl-script-box">
      <div class="pl-script-label">
        <span>${cst.icon} ${esc(cst.label)} 단계 — 추천 스크립트</span>
        <button class="sb-copy" onclick="copyPipelineScript(${p.id})">📋 복사</button>
      </div>
      <div class="pl-script-text" id="plScript_${p.id}">${esc(cst.script)}</div>
    </div>`;
  }

  return `<div class="pl-section">
    <div class="pl-title">📊 영업 파이프라인</div>
    <div class="pl-progress-wrap">
      <div class="pl-progress-bar"><div class="pl-progress-fill" style="width:${pct}%"></div></div>
      <span class="pl-pct">${completedCount}/4 · ${pct}%</span>
    </div>
    <div class="pl-stages">${stageRows}</div>
    ${histHTML}
  </div>${pipelineScriptHTML}`;
}



/* ═══ 레이어4 — 개발자도구 접근 억제 ══════════════════════════
   목적: D.people 등 메모리 데이터 콘솔 노출 방지
   한계: 완벽 차단은 불가 — 암호화(레이어2)가 진짜 방어선
════════════════════════════════════════════════════════════════ */
(function lockDevTools(){
  /* 1) 프로덕션 환경에서 console 출력 전면 차단 */
  if(location.hostname!=='localhost'&&location.hostname!=='127.0.0.1'){
    const noop=()=>{};
    ['log','warn','info','debug','table','dir','dirxml','group','groupEnd','trace','count','time','timeEnd'].forEach(m=>{
      try{ Object.defineProperty(console,m,{value:noop,writable:false,configurable:false}); }catch(e){}
    });
  }

  /* 2) 우클릭 컨텍스트 메뉴 차단 */
  document.addEventListener('contextmenu',e=>{
    e.preventDefault();
    return false;
  },{capture:true});

  /* 3) 키보드 단축키 차단
       F12 / Ctrl+Shift+I,J,C / Ctrl+U (소스 보기) / Ctrl+S (저장) */
  document.addEventListener('keydown',e=>{
    const ctrl=e.ctrlKey||e.metaKey;
    const shift=e.shiftKey;
    if(
      e.key==='F12'||
      (ctrl&&shift&&['I','i','J','j','C','c','K','k'].includes(e.key))||
      (ctrl&&['U','u','S','s'].includes(e.key))
    ){
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
  },{capture:true});

  /* 4) DevTools 열림 감지 기능 제거 — 사용성 불편으로 비활성화 */
})();


const esc = s => String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const rc     = id => D.people.filter(p=>p.ref===id).length;
const isHub  = id => rc(id)>=2;
/* 경과일 계산 — 로컬 자정 기준으로 정확히 계산 (UTC 오차 제거)
   'YYYY-MM-DD' 문자열은 로컬 자정으로 파싱, 오늘과의 일수 차 반환 */
const ago = d => {
  if(!d) return null;
  let target;
  const s = String(d);
  if(/^\d{4}-\d{2}-\d{2}$/.test(s)){
    /* 날짜만 있는 문자열 → 로컬 자정으로 해석 (T00:00:00, Z 없음) */
    const [y,m,dd] = s.split('-').map(Number);
    target = new Date(y, m-1, dd);
  } else {
    /* ISO 타임스탬프 등 → 그대로 파싱 후 해당 날짜의 로컬 자정으로 정규화 */
    const t = new Date(s);
    target = new Date(t.getFullYear(), t.getMonth(), t.getDate());
  }
  const now = new Date();
  const todayMid = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  return Math.round((todayMid - target)/86400000);
};
/* ─── 날짜 경과 텍스트 헬퍼 (음수 방지) ─── */
function daysAgoText(d){
  if(d === null) return '연락 기록 없음';
  if(d <= 0)  return '오늘 접촉';
  if(d === 1) return '어제 접촉';
  return `${d}일 전 접촉`;
}
function daysAgoShort(d){
  if(d === null) return '기록 없음';
  if(d <= 0)  return '오늘';
  if(d === 1) return '어제';
  return `${d}일 전`;
}

const nodeR  = p  => 18+Math.min(rc(p.id)*5,22);
const visible= p  => ST.filt==='all'||p.rel===ST.filt;
function lighten(hex){
  const n=parseInt(hex.slice(1),16);
  const r=Math.min(255,((n>>16)&255)+50),g=Math.min(255,((n>>8)&255)+50),b=Math.min(255,(n&255)+50);
  return '#'+(r<<16|g<<8|b).toString(16).padStart(6,'0');
}

let _toastT;
function toast(msg,ic='✅'){
  const t=document.getElementById('toast');
  t.innerHTML=ic+' '+esc(msg); t.classList.add('on');
  clearTimeout(_toastT); _toastT=setTimeout(()=>t.classList.remove('on'),2400);
}

/* ═══ 시트 시스템 ════════════════════════════════════════════════ */
const overlay=document.getElementById('overlay');
function openSheet(id){ closeSheet(); document.getElementById(id).classList.add('on'); overlay.classList.add('on'); }
function closeSheet(){ document.querySelectorAll('.sheet').forEach(s=>s.classList.remove('on')); overlay.classList.remove('on'); }
overlay.addEventListener('click',closeSheet);

/* ═══ CANVAS ════════════════════════════════════════════════════ */
const cvs=document.getElementById('cvs');
const ctx=cvs.getContext('2d');
let W=0,H=0,DPR=1;
const POS={};
let ST={ filt:'all', selId:null, editId:null, relPick:'alumni', zoom:1, ox:0, oy:0, drag:null, dragNode:null };

function resize(){
  const wrap=document.getElementById('mapWrap');
  DPR=window.devicePixelRatio||1;
  /* mapWrap이 숨겨져 있으면 clientWidth가 0 — 부모(main-container)로 대체 */
  let ww = wrap.clientWidth, wh = wrap.clientHeight;
  if(ww === 0 || wh === 0){
    const mc = document.getElementById('app');
    ww = mc ? mc.clientWidth  : window.innerWidth;
    wh = mc ? mc.clientHeight : window.innerHeight;
    /* 헤더·탭 높이 빼기 */
    const hdr = document.querySelector('.hdr');
    const nav = document.querySelector('.nav');
    wh -= (hdr ? hdr.offsetHeight : 52) + (nav ? nav.offsetHeight : 56);
    wh = Math.max(wh, 200);
  }
  W = ww; H = wh;
  cvs.width=W*DPR; cvs.height=H*DPR;
  cvs.style.width=W+'px'; cvs.style.height=H+'px';
  ctx.setTransform(DPR,0,0,DPR,0,0);
}
const w2s=(x,y)=>({sx:x*ST.zoom+ST.ox,sy:y*ST.zoom+ST.oy});
const s2w=(sx,sy)=>({x:(sx-ST.ox)/ST.zoom,y:(sy-ST.oy)/ST.zoom});

/* ── 허브 중심 계층 정적 레이아웃 ──────────────────────────────
   규칙:
   1) 허브(소개 2명+)는 화면 중심 가까이 배치
   2) 각 허브 주변에 그 자식들을 원형으로 배치
   3) 루트 노드(ref 없는)는 허브가 아니면 외곽 배치
   4) 노드 겹침 방지: 최소 간격 = (r1+r2+20)px
   5) 한 번 배치하면 고정 (물리 시뮬 없음)
──────────────────────────────────────────────────────────────── */

function initPos(){
  /* 캔버스 크기 준비 안 된 경우 보정 */
  if(W===0||H===0) return;

  const ppl = D.people;
  if(!ppl.length) return;

  /* 이미 위치 있는 노드는 그대로 유지 (추가된 노드만 새로 배치) */
  const newNodes = ppl.filter(p=>!POS[p.id]);
  if(!newNodes.length) return;

  /* 전체 재배치 필요 여부: 처음 배치이거나 삭제/추가 비율이 크면 재계산 */
  const needFull = Object.keys(POS).length === 0;

  if(needFull){
    _doFullLayout(ppl);
  } else {
    /* 신규 노드만 빈 자리에 삽입 */
    newNodes.forEach(p => _placeNewNode(p, ppl));
  }
}

function _doFullLayout(ppl){
  const cx = W/2, cy = H/2;
  const placed = new Set();

  /* 자손 수 추정 (각도 분배용) */
  function subtreeSize(p){
    const children = ppl.filter(c=>c.ref===p.id);
    if(!children.length) return 1;
    return children.reduce((s,c)=>s+subtreeSize(c), 0);
  }

  /* 재귀 트리 배치
     px/py: 부모 위치, angle: 부모→나 방향, depth: 깊이, spread: 허용 각도 */
  function placeTree(p, px, py, angle, depth, spread){
    if(placed.has(p.id)) return;
    const myR = nodeR(p);
    const dist = Math.max(myR * 2 + 55, 105 - depth * 6);
    const x = _clamp(px + Math.cos(angle) * dist, 46, W-46);
    const y = _clamp(py + Math.sin(angle) * dist, 46, H-46);
    POS[p.id] = { x, y };
    placed.add(p.id);

    const children = ppl.filter(c => c.ref === p.id && !placed.has(c.id));
    if(!children.length) return;
    const childSpread = Math.min(spread * 0.88, Math.PI * 1.5);
    const sizes = children.map(c => Math.max(1, subtreeSize(c)));
    const total = sizes.reduce((s,v)=>s+v, 0);
    let cum = angle - childSpread / 2;
    children.forEach((child, i) => {
      const slice = (sizes[i] / total) * childSpread;
      placeTree(child, x, y, cum + slice/2, depth+1, slice);
      cum += slice;
    });
  }

  /* 루트(ref 없는 노드 또는 부모 없는 고아) */
  const roots = ppl.filter(p => {
    if(!p.ref) return true;
    return !ppl.find(q=>q.id===p.ref);
  });

  if(roots.length === 1){
    const root = roots[0];
    POS[root.id] = { x: cx, y: cy };
    placed.add(root.id);
    const children = ppl.filter(c=>c.ref===root.id);
    const n = children.length || 1;
    const sizes = children.map(c=>Math.max(1, subtreeSize(c)));
    const total = sizes.reduce((s,v)=>s+v, 0);
    let cum = -Math.PI/2;
    children.forEach((child, i) => {
      const slice = (sizes[i]/total) * Math.PI * 2;
      placeTree(child, cx, cy, cum + slice/2, 1, slice);
      cum += slice;
    });
  } else {
    const rootR = Math.min(W, H) * 0.26;
    roots.forEach((root, i) => {
      const angle = (i/roots.length)*Math.PI*2 - Math.PI/2;
      const rx = _clamp(cx + Math.cos(angle)*rootR, 46, W-46);
      const ry = _clamp(cy + Math.sin(angle)*rootR, 46, H-46);
      POS[root.id] = { x: rx, y: ry };
      placed.add(root.id);
      const children = ppl.filter(c=>c.ref===root.id);
      const n = children.length || 1;
      const spread = Math.PI * 1.4;
      const sizes = children.map(c=>Math.max(1, subtreeSize(c)));
      const total = sizes.reduce((s,v)=>s+v, 0);
      let cum = angle - spread/2;
      children.forEach((child, i) => {
        const slice = (sizes[i]/total)*spread;
        placeTree(child, rx, ry, cum+slice/2, 1, slice);
        cum += slice;
      });
    });
  }

  /* 미배치 고아 외곽 */
  const remaining = ppl.filter(p=>!placed.has(p.id));
  remaining.forEach((p,i)=>{
    const a=(i/Math.max(1,remaining.length))*Math.PI*2;
    POS[p.id]={ x:_clamp(cx+Math.cos(a)*Math.min(W,H)*0.42,46,W-46), y:_clamp(cy+Math.sin(a)*Math.min(W,H)*0.42,46,H-46) };
  });

  /* 겹침 해소 — 40회 */
  for(let pass=0; pass<40; pass++) _resolveOverlaps(ppl);
}

function _placeNewNode(p, ppl){
  let bx = W*0.8, by = 60;
  if(p.ref && POS[p.ref]){
    const parent = POS[p.ref];
    const siblings = ppl.filter(q=>q.ref===p.ref && POS[q.id] && q.id!==p.id);
    const usedAngles = siblings.map(s=>Math.atan2(POS[s.id].y-parent.y, POS[s.id].x-parent.x));
    let bestA=0, bestGap=0;
    for(let a=0; a<Math.PI*2; a+=0.15){
      const gap = usedAngles.length
        ? usedAngles.reduce((mn,ua)=>{ let d=Math.abs(ua-a); if(d>Math.PI)d=Math.PI*2-d; return Math.min(mn,d); }, Math.PI*2)
        : Math.PI*2;
      if(gap>bestGap){ bestGap=gap; bestA=a; }
    }
    const pn = ppl.find(q=>q.id===p.ref)||p;
    const dist = nodeR(pn)+nodeR(p)+55;
    bx = _clamp(parent.x+Math.cos(bestA)*dist, 46, W-46);
    by = _clamp(parent.y+Math.sin(bestA)*dist, 46, H-46);
  }
  POS[p.id]={x:bx, y:by};
  for(let i=0; i<15; i++) _resolveOverlaps(ppl);
}

function _resolveOverlaps(ppl){
  for(let i=0; i<ppl.length; i++){
    for(let j=i+1; j<ppl.length; j++){
      const a=ppl[i], b=ppl[j];
      const pa=POS[a.id], pb=POS[b.id];
      if(!pa||!pb) continue;
      const minDist = nodeR(a)+nodeR(b)+28;
      const dx=pb.x-pa.x, dy=pb.y-pa.y;
      const d=Math.sqrt(dx*dx+dy*dy)||0.1;
      if(d<minDist){
        const push=(minDist-d)/2+2;
        const nx=dx/d, ny=dy/d;
        const wa=isHub(a.id)?0.1:0.5;
        const wb=isHub(b.id)?0.1:0.5;
        pa.x=_clamp(pa.x-nx*push*wa, 30, W-30);
        pa.y=_clamp(pa.y-ny*push*wa, 30, H-30);
        pb.x=_clamp(pb.x+nx*push*wb, 30, W-30);
        pb.y=_clamp(pb.y+ny*push*wb, 30, H-30);
      }
    }
  }
}

function _clamp(v, lo, hi){ return Math.max(lo, Math.min(hi, v)); }

/* 연결망 전체 재배치 (노드 추가/삭제 후 호출) */
function relayout(){
  Object.keys(POS).forEach(k => delete POS[k]);
  /* 연결망 뷰가 보이는 상태면 즉시 배치, 숨겨져 있으면 플래그만 세움 */
  const mapVisible = document.getElementById('vMap').classList.contains('show');
  if(mapVisible){
    resize();   /* 최신 크기 반영 */
    initPos();
  }
  /* mapVisible이 false면 showMainView('vMap') 호출 시 initPos가 실행됨 */
}

function draw(){
  ctx.clearRect(0,0,W,H);
  /* 엣지 */
  for(const p of D.people){
    if(!p.ref) continue;
    const a=POS[p.ref],b=POS[p.id]; if(!a||!b) continue;
    const pa=w2s(a.x,a.y),pb=w2s(b.x,b.y);
    const refP=D.people.find(x=>x.id===p.ref)||{rel:'all'};
    const show=visible(p)&&visible(refP);
    ctx.lineWidth=show?1.8:0.5;
    const g2=ctx.createLinearGradient(pa.sx,pa.sy,pb.sx,pb.sy);
    g2.addColorStop(0,show?'rgba(100,140,200,.55)':'rgba(0,0,0,.04)');
    g2.addColorStop(1,show?'rgba(60,100,180,.22)':'rgba(0,0,0,.02)');
    ctx.strokeStyle=g2;
    ctx.beginPath(); ctx.moveTo(pa.sx,pa.sy);
    ctx.quadraticCurveTo((pa.sx+pb.sx)/2,(pa.sy+pb.sy)/2-12,pb.sx,pb.sy);
    ctx.stroke();
    if(show){
      const ang=Math.atan2(pb.sy-pa.sy,pb.sx-pa.sx),rr=nodeR(p)*ST.zoom;
      const ax=pb.sx-Math.cos(ang)*rr,ay=pb.sy-Math.sin(ang)*rr;
      ctx.fillStyle='rgba(80,130,220,.55)';
      ctx.beginPath(); ctx.moveTo(ax,ay);
      ctx.lineTo(ax-Math.cos(ang-.45)*7,ay-Math.sin(ang-.45)*7);
      ctx.lineTo(ax-Math.cos(ang+.45)*7,ay-Math.sin(ang+.45)*7);
      ctx.closePath(); ctx.fill();
    }
  }
  /* 노드 */
  for(const p of D.people){
    const pp=POS[p.id]; if(!pp) continue;
    const s=w2s(pp.x,pp.y),r=nodeR(p)*ST.zoom,show=visible(p),hub=isHub(p.id),sel=ST.selId===p.id;
    const col=REL[p.rel].col;
    if(!show){ ctx.beginPath(); ctx.arc(s.sx,s.sy,r*.5,0,Math.PI*2); ctx.fillStyle='rgba(0,0,0,.06)'; ctx.fill(); continue; }
    if(hub||sel){
      const gr=ctx.createRadialGradient(s.sx,s.sy,0,s.sx,s.sy,r*2.4);
      gr.addColorStop(0,col+(sel?'44':'28')); gr.addColorStop(1,'transparent');
      ctx.beginPath(); ctx.arc(s.sx,s.sy,r*2.4,0,Math.PI*2); ctx.fillStyle=gr; ctx.fill();
    }
    const bg=ctx.createRadialGradient(s.sx-r*.25,s.sy-r*.25,0,s.sx,s.sy,r);
    bg.addColorStop(0,lighten(col)); bg.addColorStop(1,col);
    ctx.beginPath(); ctx.arc(s.sx,s.sy,r,0,Math.PI*2); ctx.fillStyle=bg; ctx.fill();
    ctx.lineWidth=sel?3.5:(hub?2.2:1.2);
    ctx.strokeStyle=sel?'#fff':(hub?'rgba(255,255,255,.85)':'rgba(255,255,255,.3)'); ctx.stroke();
    ctx.fillStyle='rgba(255,255,255,.95)'; ctx.textAlign='center'; ctx.textBaseline='middle';
    ctx.font=`700 ${Math.max(11,r*.78)}px Pretendard,sans-serif`;
    ctx.fillText((p.name||'?').charAt(0),s.sx,s.sy);
    if(hub){ ctx.font=`${Math.max(10,r*.6)}px Arial`; ctx.fillText('⭐',s.sx+r*.72,s.sy-r*.72); }
    if(ST.zoom>.7){
      ctx.font=`600 ${Math.max(10,11*Math.min(ST.zoom,1.4))}px Pretendard,sans-serif`;
      ctx.fillStyle='rgba(50,30,10,.8)';
      ctx.fillText(p.name||'?',s.sx,s.sy+r+11);
    }
  }
}
/* 물리 시뮬 없음 — draw만 rAF로 반복 (드래그 반응용) */
function loop(){ draw(); requestAnimationFrame(loop); }

/* ── 터치/마우스 인터랙션 ── */
function nodeAt(sx,sy){
  for(let i=D.people.length-1;i>=0;i--){
    const p=D.people[i]; if(!visible(p)) continue;
    const pp=POS[p.id]; if(!pp) continue;
    const s=w2s(pp.x,pp.y),r=nodeR(p)*ST.zoom;
    if(Math.hypot(sx-s.sx,sy-s.sy)<=r+6) return p;
  } return null;
}
function gxy(e){
  const r=cvs.getBoundingClientRect();
  const t=(e.touches&&e.touches.length>0)?e.touches[0]:(e.changedTouches&&e.changedTouches.length>0)?e.changedTouches[0]:e;
  return{x:t.clientX-r.left,y:t.clientY-r.top};
}
let moved=false,sp=null,tapId=null,pDist=0,pinching=false;
function resetDrag(){ ST.drag=null; ST.dragNode=null; moved=false; tapId=null; }
function onDn(e){
  if(e.touches&&e.touches.length>1){pinching=true;resetDrag();return;}
  pinching=false;
  const{x,y}=gxy(e); sp={x,y}; moved=false;
  const n=nodeAt(x,y);
  if(n){ST.dragNode=n.id;tapId=n.id;ST.drag={x,y};}
  else{tapId=null;ST.drag={x,y,ps:{ox:ST.ox,oy:ST.oy}};}
}
function onMv(e){
  if(pinching||!ST.drag)return;
  const{x,y}=gxy(e);
  if(Math.hypot(x-sp.x,y-sp.y)>10){moved=true;tapId=null;}
  if(ST.dragNode){const w=s2w(x,y);POS[ST.dragNode].x=w.x;POS[ST.dragNode].y=w.y;}
  else if(ST.drag.ps){ST.ox=ST.drag.ps.ox+(x-ST.drag.x);ST.oy=ST.drag.ps.oy+(y-ST.drag.y);}
}
function onUp(){
  if(pinching){pinching=false;pDist=0;resetDrag();return;}
  if(!moved&&tapId!==null){const id=tapId;resetDrag();openDetail(id);return;}
  resetDrag();
}
// 마우스
cvs.addEventListener('mousedown',onDn);
window.addEventListener('mousemove',e=>{
  onMv(e);
  if(!ST.drag){
    const{x,y}=gxy(e),n=nodeAt(x,y),tip=document.getElementById('tip');
    if(n){cvs.style.cursor='pointer';tip.style.cssText=`display:block;left:${x+14}px;top:${y-8}px`;tip.textContent=n.name+' · '+REL[n.rel].sh+(rc(n.id)?` · 소개 ${rc(n.id)}명`:'');}
    else{cvs.style.cursor='default';tip.style.display='none';}
  }
});
window.addEventListener('mouseup',onUp);
// 터치 — 모두 passive:false
cvs.addEventListener('touchstart',e=>{
  if(e.touches.length===2){
    pinching=true; pDist=Math.hypot(e.touches[0].clientX-e.touches[1].clientX,e.touches[0].clientY-e.touches[1].clientY);
    ST.drag=null; ST.dragNode=null; e.preventDefault(); return;
  }
  onDn(e); e.preventDefault();
},{passive:false});
cvs.addEventListener('touchmove',e=>{
  if(e.touches.length===2&&pinching){
    const d=Math.hypot(e.touches[0].clientX-e.touches[1].clientX,e.touches[0].clientY-e.touches[1].clientY);
    if(pDist>0){
      const scale=d/pDist,r=cvs.getBoundingClientRect();
      const mx=(e.touches[0].clientX+e.touches[1].clientX)/2-r.left;
      const my=(e.touches[0].clientY+e.touches[1].clientY)/2-r.top;
      ST.ox=mx-(mx-ST.ox)*scale; ST.oy=my-(my-ST.oy)*scale;
      ST.zoom=Math.max(.3,Math.min(3.5,ST.zoom*scale));
    }
    pDist=d; e.preventDefault(); return;
  }
  if(e.touches.length===1){onMv(e);e.preventDefault();}
},{passive:false});
cvs.addEventListener('touchend',  e=>{if(e.touches.length===0)pinching=false;onUp();},{passive:false});
cvs.addEventListener('touchcancel',()=>{resetDrag();pinching=false;pDist=0;});
cvs.addEventListener('wheel',e=>{
  e.preventDefault();
  const{x,y}=gxy(e),f=e.deltaY>0?.88:1.14;
  ST.ox=x-(x-ST.ox)*f; ST.oy=y-(y-ST.oy)*f; ST.zoom=Math.max(.3,Math.min(3.5,ST.zoom*f));
},{passive:false});
// 줌 버튼
document.getElementById('btnZoomIn').onclick   =()=>{ST.zoom=Math.min(3.5,ST.zoom*1.2);};
document.getElementById('btnZoomOut').onclick  =()=>{ST.zoom=Math.max(.3,ST.zoom/1.2);};
document.getElementById('btnZoomReset').onclick=()=>{ST.zoom=1;ST.ox=ST.oy=0;toast('화면 초기화');};
// 필터
document.getElementById('filterBar').addEventListener('click',e=>{
  const pill=e.target.closest('.fpill'); if(!pill) return;
  document.querySelectorAll('.fpill').forEach(p=>{p.classList.remove('on');p.style.cssText='';});
  pill.classList.add('on'); ST.filt=pill.dataset.f;
  const c=pill.dataset.f==='all'?'var(--brand)':REL[pill.dataset.f].col;
  pill.style.cssText=`background:${c};color:#fff;border-color:${c};`;
});

/* ═══ 인맥 폼 ════════════════════════════════════════════════════ */
document.getElementById('fabAdd').addEventListener('click',()=>openForm());
/* ─── 인맥 추가/수정 폼 2단계 ─── */
function showFormStep(step){
  document.getElementById('formStep1').style.display = step===1?'block':'none';
  document.getElementById('formStep2').style.display = step===2?'block':'none';
}

function openForm(editId){
  ST.editId=editId||null;
  const isEdit=!!editId;
  document.getElementById('formTitle').textContent=isEdit?'인맥 수정':'인맥 추가';

  /* 소개해준사람 목록 채우기 */
  const sel=document.getElementById('fRef');
  sel.innerHTML='<option value="">— 직접 알게 됨 —</option>';
  D.people.filter(p=>p.id!==editId).forEach(p=>{
    sel.innerHTML+=`<option value="${p.id}">${esc(p.name)}</option>`;
  });

  const etcInput=document.getElementById('fGroupEtc');

  if(isEdit){
    /* 수정 시: 2단계 폼으로 바로 표시 */
    const p=D.people.find(x=>x.id===editId);
    ST.relPick=normalizeRel(p.rel);
    document.getElementById('fName').value=p.name||'';
    sel.value=p.ref||'';
    document.getElementById('fDate').value=p.lastContact||'';
    document.getElementById('fMemo').value=p.memo||'';
    document.querySelectorAll('.rel-opt').forEach(o=>{
      o.classList.toggle('selected',o.dataset.r===ST.relPick);
      if(o.dataset.r===ST.relPick) o.style.background=REL[ST.relPick].col;
      else o.style.background='';
    });
    /* 기타 그룹이면 직접입력 필드 표시 + 값 채우기 */
    if(ST.relPick==='etc'){
      etcInput.style.display='block';
      etcInput.value=p.group||'';
    } else {
      etcInput.style.display='none'; etcInput.value='';
    }
    showFormStep(2);
  } else {
    /* 추가 시: 1단계부터 */
    ST.relPick='alumni';
    document.getElementById('fName').value='';
    sel.value='';
    document.getElementById('fDate').value='';
    document.getElementById('fMemo').value='';
    etcInput.style.display='none'; etcInput.value='';
    document.querySelectorAll('.rel-opt').forEach(o=>{
      o.classList.remove('selected'); o.style.background='';
    });
    /* 동창 기본 선택 */
    const defOpt=document.querySelector('.rel-opt[data-r="alumni"]');
    if(defOpt){ defOpt.classList.add('selected'); defOpt.style.background=REL['alumni'].col; }
    showFormStep(1);
  }
  openSheet('shForm');
}
document.getElementById('relRow').addEventListener('click',e=>{
  const o=e.target.closest('.rel-opt'); if(!o) return;
  ST.relPick=o.dataset.r;
  document.querySelectorAll('.rel-opt').forEach(x=>{x.classList.remove('selected');x.style.background='';});
  o.classList.add('selected'); o.style.background=REL[o.dataset.r].col;
  /* "기타" 선택 시 직접입력 필드 표시 */
  const etcInput=document.getElementById('fGroupEtc');
  if(etcInput){
    if(o.dataset.r==='etc'){ etcInput.style.display='block'; }
    else { etcInput.style.display='none'; etcInput.value=''; }
  }
});

/* ── 2단계 폼 이벤트 ── */
document.getElementById('btnStep1Next').addEventListener('click',()=>{
  const name=document.getElementById('fName').value.trim();
  if(!name){toast('이름을 입력하세요','⚠');return;}
  if(!guardSensitive([{id:'fName',label:'이름/별칭'}])) return;
  showFormStep(2);
});
document.getElementById('btnStep1Skip').addEventListener('click',()=>{
  const name=document.getElementById('fName').value.trim();
  if(!name){toast('이름을 입력하세요','⚠');return;}
  if(!guardSensitive([{id:'fName',label:'이름/별칭'}])) return;
  const refVal = document.getElementById('fRef').value;
  const etcVal = ST.relPick==='etc' ? document.getElementById('fGroupEtc').value.trim() : '';
  const obj={name,rel:ST.relPick,region:'',group:etcVal,ref:refVal?+refVal:null,lastContact:'',memo:''};
  if(ST.editId){
    const eid = ST.editId;
    Object.assign(D.people.find(x=>x.id===eid),obj);
    toast(name+' 수정 완료','✏');
    save(); refresh(); closeSheet();
    setTimeout(()=>openDetail(eid), 200);
  } else {
    obj.id=D.nid++;obj.created=new Date().toISOString();D.people.push(obj);
    toast(name+' 추가 완료 — 나중에 상세정보를 채워보세요','✅');
    save(); refresh(); closeSheet();
  }
});
document.getElementById('btnStep2Back').addEventListener('click',()=>showFormStep(1));

/* fabAddToday → 오늘 뷰에서 추가 */
document.getElementById('fabAddToday').addEventListener('click',()=>openForm());
/* ═══ 민감정보 입력 차단 ════════════════════════════════════════
   차단 패턴:
   ① 연속 6자리 이상 숫자 (주민번호 앞자리·뒷자리, 계좌번호 등)
   ② 전화번호 형식: 010-XXXX-XXXX / 010XXXXXXXX
   ③ 주민번호 형식: XXXXXX-XXXXXXX / XXXXXXXXXXXXX (13자리 연속)
   ④ 이메일 패턴 (개인정보 수집 방지)
═══════════════════════════════════════════════════════════════ */
const SENSITIVE_PATTERNS = [
  {
    /* 6자리 이상 연속 숫자 — 단, 연도(20xx, 19xx) 단독 표현은 허용 */
    re: /(?<!\d)(?!(?:19|20)\d{2}(?!\d))\d{6,}/,
    msg: '연속된 숫자 6자리 이상은 입력할 수 없습니다\n(주민번호·계좌번호 등 민감정보 보호)',
  },
  {
    re: /01[016789][^\d]?\d{3,4}[^\d]?\d{4}/,
    msg: '휴대폰 번호는 입력할 수 없습니다',
  },
  {
    re: /[가-힣a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
    msg: '이메일 주소는 입력할 수 없습니다',
  },
];

/**
 * 민감정보 검사
 * @param {string} text 검사할 문자열
 * @returns {string|null} 위반 메시지 또는 null(통과)
 */
function checkSensitive(text) {
  if (!text) return null;
  for (const { re, msg } of SENSITIVE_PATTERNS) {
    if (re.test(text)) return msg;
  }
  return null;
}

/**
 * 필드 + 경고 UI 연결 — 입력 중 실시간 감지
 * @param {HTMLElement} el  input 또는 textarea
 * @param {HTMLElement} warn 경고 문구 표시용 요소 (hint-warn)
 */
function bindSensitiveCheck(el, warn) {
  if (!el) return;
  el.addEventListener('input', () => {
    const msg = checkSensitive(el.value);
    if (msg) {
      warn.textContent = '🚫 ' + msg;
      warn.style.color = 'var(--red)';
      warn.style.fontWeight = '700';
      el.style.borderColor = 'var(--red)';
    } else {
      warn.textContent = '⚠ 주민번호·연락처·계약금액 등 민감정보는 입력하지 마세요';
      warn.style.color = '';
      warn.style.fontWeight = '';
      el.style.borderColor = '';
    }
  });
}

/* 인맥 추가 폼의 이름·지역·메모 필드에 실시간 감지 적용 */
(function initSensitiveBindings() {
  const warnEl = document.querySelector('.hint-warn');
  if (!warnEl) return;
  ['fName', 'fMemo'].forEach(id => {
    bindSensitiveCheck(document.getElementById(id), warnEl);
  });
  /* 일정 폼 장소·메모에도 적용 */
  const schedWarn = document.querySelector('#shSched .hint-warn');
  if (schedWarn) {
    bindSensitiveCheck(document.getElementById('sMemo'), schedWarn);
  }
})();

/**
 * 저장 전 최종 민감정보 검사 — 통과하면 true 반환
 * fields: [{id, label}]
 */
function guardSensitive(fields) {
  for (const { id, label } of fields) {
    const el = document.getElementById(id);
    if (!el) continue;
    const msg = checkSensitive(el.value);
    if (msg) {
      toast(`[${label}] ${msg}`, '🚫');
      el.focus();
      el.style.borderColor = 'var(--red)';
      setTimeout(() => { el.style.borderColor = ''; }, 2000);
      return false;
    }
  }
  return true;
}

document.getElementById('btnSave').addEventListener('click',()=>{
  const name=document.getElementById('fName').value.trim();
  if(!name){toast('이름을 입력하세요','⚠');return;}
  /* 민감정보 최종 검사 */
  if(!guardSensitive([
    {id:'fName',   label:'이름/별칭'},
    {id:'fMemo',   label:'메모'},
  ])) return;
  const obj={
    name, rel:ST.relPick,
    region:'',
    group:ST.relPick==='etc' ? document.getElementById('fGroupEtc').value.trim() : '',
    ref:document.getElementById('fRef').value?+document.getElementById('fRef').value:null,
    lastContact:document.getElementById('fDate').value,
    memo:document.getElementById('fMemo').value.trim(),
  };
  if(ST.editId){
    const eid = ST.editId;
    Object.assign(D.people.find(x=>x.id===eid),obj);
    toast(name+' 수정 완료','✏');
    save(); refresh(); closeSheet();
    setTimeout(()=>openDetail(eid), 200);
  } else {
    obj.id=D.nid++;obj.created=new Date().toISOString();D.people.push(obj);
    toast(name+' 추가','✅');
    save(); refresh(); closeSheet();
  }
});

/* ═══ 상세 보기 ══════════════════════════════════════════════════ */

function openDetail(id){
  const p=D.people.find(x=>x.id===id); if(!p) return;
  ST.selId=id;
  const col=REL[p.rel].col, rcN=rc(id), hub=isHub(id);
  const refP=p.ref?D.people.find(x=>x.id===p.ref):null;
  const kids=D.people.filter(x=>x.ref===id);
  let lastTxt='없음',dayTxt='';
  if(p.lastContact){const d=ago(p.lastContact);lastTxt=p.lastContact;dayTxt=d!==null&&d<=0?'(오늘)':`(${daysAgoShort(d)})`;}
  // 소개 경로
  let chain=[p],cur=p;
  for(let i=0;i<5;i++){const nx=cur.ref?D.people.find(x=>x.id===cur.ref):null;if(!nx)break;chain.push(nx);cur=nx;}
  chain.reverse();
  const pathHTML=chain.length>1?chain.map(x=>`<span style="color:${REL[x.rel].col};font-weight:600">${esc(x.name)}</span>`).join(' → '):'없음';

  /* ── 연계2: 오늘할일 이유 배지 ── */
  let todayBadgeHTML = '';
  const _cls = classifyPerson(p);
  if(_cls){
    const isOpp = _cls.type === 'opportunity';
    todayBadgeHTML = `<div class="det-today-badge ${isOpp?'opp':'mgmt'}">
      ${isOpp ? '🌟 소개 요청 적기' : '📞 안부 연락 필요'} &nbsp;·&nbsp; ${esc(_cls.reason)}
    </div>`;
  }

  /* ── 관계 온도 계산 ── */
  const tempScore = calcRelationshipTemp(p);
  const tempHTML  = renderTempHTML(tempScore);

  /* ── 내가 소개한 사람 현황 ── */
  let referralStatusHTML = '';
  const myReferrals = D.people.filter(x=>x.ref===id);
  if(myReferrals.length > 0){
    const items = myReferrals.map(r=>{
      const pl=ensurePipeline(r);
      const done=pl.dates.filter(Boolean).length;
      const st=done>0?PIPELINE_STAGES[Math.min(done-1,3)]:null;
      const stLabel=st?`${st.icon} ${st.label}`:'미시작';
      const stCol=st?st.col:'var(--txt3)';
      return `<div class="referral-row">
        <div class="referral-av" style="background:${REL[r.rel].col}">${esc((r.name||'?').charAt(0))}</div>
        <div class="referral-info">
          <div class="referral-name">${esc(r.name)}<span class="pbadge" style="background:${REL[r.rel].col}22;color:${REL[r.rel].col};margin-left:6px">${REL[r.rel].sh}</span></div>
          <div class="referral-stage" style="color:${stCol}">${stLabel}</div>
        </div>
        <button class="referral-go" onclick="closeSheet();setTimeout(()=>openDetail(${r.id}),200)">›</button>
      </div>`;
    }).join('');
    referralStatusHTML=`<div class="referral-section">
      <div class="referral-title">🔗 내가 소개한 사람 현황 (${myReferrals.length}명)</div>
      ${items}
    </div>`;
  }

  document.getElementById('detBody').innerHTML=`
    ${todayBadgeHTML}
    <div class="d-hero">
      <div class="d-av" style="background:linear-gradient(135deg,${lighten(col)},${col})">${esc((p.name||'?').charAt(0))}</div>
      <div class="d-name">${esc(p.name)}${hub?' ⭐':''}</div>
      <div class="d-sub">${esc(groupNameOf(p))}</div>
      <div class="d-chips">
        <span class="dchip" style="background:${col}22;color:${col}">${rcN}명 소개</span>
        ${hub?`<span class="dchip" style="background:var(--green-bg);color:var(--green)">핵심 허브</span>`:''}
        ${refP?`<span class="dchip" style="background:var(--blue-bg);color:var(--blue)">${esc(refP.name)} 소개</span>`:'<span class="dchip" style="background:#F5F0EB;color:var(--txt3)">직접 인맥</span>'}
      </div>
    </div>
    ${tempHTML}
    <div class="kv-box">
      <div class="kv"><span class="k">소개해 준 사람</span><span class="v">${refP?esc(refP.name):'직접 알게 됨'}</span></div>
      <div class="kv"><span class="k">소개 경로</span><span class="v" style="max-width:64%;text-align:right">${pathHTML}</span></div>
      <div class="kv"><span class="k">소개받은 인맥</span><span class="v">${kids.length?kids.map(x=>esc(x.name)).join(', '):'없음'}</span></div>
      <div class="kv"><span class="k">최근 접촉</span><span class="v">${esc(lastTxt)} <span style="color:var(--txt3)">${esc(dayTxt)}</span></span></div>
      ${p.memo?`<div class="kv"><span class="k">메모</span><span class="v" style="max-width:60%">${esc(p.memo)}</span></div>`:''}
    </div>
    ${renderPipelineHTML(p)}
    ${renderContactResultHTML(p)}
    ${referralStatusHTML}
    <button class="btn btn-primary" onclick="markContact(${id})">📞 오늘 접촉함 · 타이밍 갱신</button>
    <button class="btn btn-ghost"   onclick="openSchedFromDetail(${id})">📅 이 분과 미팅 일정 추가</button>
    <button class="btn btn-ghost"   onclick="addReferred(${id})">🔗 이 사람이 소개한 인맥 추가</button>
    <button class="btn btn-ghost"   onclick="openForm(${id})">✏ 수정</button>
    <button class="btn btn-danger"  onclick="delPerson(${id})">🗑 삭제</button>
  `;
  openSheet('shDetail');
}
function markContact(id){
  const p=D.people.find(x=>x.id===id);
  if(!p) return;
  const today=toDateStr(new Date());
  p.lastContact=today;
  /* contactLog에도 기록 — classifyPerson의 recentlyActed 판단에 사용 */
  if(!p.contactLog) p.contactLog=[];
  /* 오늘 이미 기록됐으면 중복 추가 안 함 */
  if(!p.contactLog.some(l=>l.date===today)){
    p.contactLog.push({ date:today, result:'contact' });
  }
  save(); refresh(); openDetail(id); toast('접촉일 오늘로 갱신','📞');
}

/* 연계1: 상세 시트 → 이 인물로 미팅 일정 바로 추가 */
function openSchedFromDetail(personId){
  closeSheet();
  setTimeout(()=>{
    openSchedForm(null);
    /* 인물 선택 자동 설정 + 파이프라인 자동반영 */
    const sel = document.getElementById('sPerson');
    if(sel){ sel.value = personId; onSchedPersonChange(); }
    /* 날짜 오늘로 기본 설정 */
    const dateEl = document.getElementById('sDate');
    if(dateEl && !dateEl.value) dateEl.value = toDateStr(new Date());
  }, 220);
}

/* ─── 소개 요청 결과 기록 ─── */
const CONTACT_RESULTS = [
  { key:'success', label:'소개해줌 ✅', col:'#15803D', bg:'#ECFDF5' },
  { key:'refuse',  label:'거절함 ❌',   col:'#DC2626', bg:'#FEF2F2' },
  { key:'pending', label:'나중에 🕐',   col:'#D97706', bg:'#FFFBEB' },
];

function recordContactResult(personId, resultKey){
  const p=D.people.find(x=>x.id===personId); if(!p) return;
  if(!p.contactLog) p.contactLog=[];
  const _rToday=toDateStr(new Date());
  p.contactLog.push({ date:_rToday, result:resultKey });
  p.lastContact=_rToday;
  save(); refresh(); openDetail(personId);
  const r=CONTACT_RESULTS.find(x=>x.key===resultKey);
  if(r) toast('소개 요청 결과 기록: '+r.label, '📝');
}

function renderContactResultHTML(p){
  const log = (p.contactLog||[]).filter(l => l.result && l.result !== 'contact');
  const successCount = log.filter(l=>l.result==='success').length;
  const lastResult = log.length ? log[log.length-1] : null;
  const recent = [...log].reverse().slice(0,5);

  /* 마지막 결과 상태 배너 */
  let statusBanner = '';
  if(lastResult){
    const r = CONTACT_RESULTS.find(x=>x.key===lastResult.result);
    if(r){
      const d = ago(lastResult.date);
      const dayStr = daysAgoShort(d);
      statusBanner = `<div class="cr-status" style="background:${r.bg};border:1px solid ${r.col}33;color:${r.col}">
        마지막 요청 결과: ${r.label} · ${dayStr}
      </div>`;
    }
  }

  const resultBtns = CONTACT_RESULTS.map(r=>
    `<button class="cr-btn" style="background:${r.bg};color:${r.col};border-color:${r.col}44"
      onclick="recordContactResult(${p.id},'${r.key}')">${r.label}</button>`
  ).join('');

  const successBadge = successCount > 0
    ? `<span class="cr-success-badge">소개 성공 ${successCount}회</span>` : '';

  let histHTML = '';
  if(recent.length){
    histHTML = `<div class="cr-hist">
      <div class="cr-hist-title">최근 요청 이력 ${successBadge}</div>`
      + recent.map(l=>{
        const r=CONTACT_RESULTS.find(x=>x.key===l.result)||{label:l.result,col:'#9C8878'};
        return `<div class="cr-hist-row">
          <span class="cr-hist-date">${l.date}</span>
          <span class="cr-hist-result" style="color:${r.col}">${r.label}</span>
        </div>`;
      }).join('') + `</div>`;
  }

  return `<div class="cr-section">
    <div class="cr-title">🤝 소개 요청</div>
    ${statusBanner}
    <div class="cr-desc">소개를 요청한 결과를 기록하세요. 여러 번 반복 요청이 가능합니다.</div>
    <div class="cr-btns">${resultBtns}</div>
    ${histHTML}
  </div>`;
}

function copyPipelineScript(id){
  const p=D.people.find(x=>x.id===id); if(!p) return;
  const pl=ensurePipeline(p);
  const curStageIdx=pl.dates.filter(Boolean).length-1;
  if(curStageIdx<0||curStageIdx>=PIPELINE_STAGES.length) return;
  const text=PIPELINE_STAGES[curStageIdx].script;
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(text)
      .then(()=>toast('파이프라인 스크립트 복사 완료','📋'))
      .catch(()=>_fallbackCopy(text));
  } else {
    _fallbackCopy(text);
  }
}
function _fallbackCopy(text){
  const ta=document.createElement('textarea');
  ta.value=text; ta.style.cssText='position:fixed;opacity:0;top:0;left:0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try{ document.execCommand('copy'); toast('스크립트가 복사됐습니다','📋'); }
  catch{ toast('복사 실패 — 직접 선택해 주세요','⚠'); }
  document.body.removeChild(ta);
}
function delPerson(id){
  const p=D.people.find(x=>x.id===id);
  if(!p) return;
  if(!confirm(`${p.name}님을 삭제할까요?`)) return;
  /* 소개 관계 해제 */
  D.people.filter(x=>x.ref===id).forEach(x=>x.ref=null);
  D.people=D.people.filter(x=>x.id!==id);
  delete POS[id];
  /* 버그1 fix: 이 인물에 연결된 일정 personId 초기화 (일정은 유지, 인물 연결만 해제) */
  SCHEDS.forEach(s=>{ if(s.personId===id) s.personId=null; });
  saveScheds();
  save(); refresh(); closeSheet(); toast('삭제됐습니다','🗑');
}
function addReferred(id){const p=D.people.find(x=>x.id===id);closeSheet();setTimeout(()=>{openForm();document.getElementById('fRef').value=id;document.getElementById('formTitle').textContent=`${p.name}님이 소개한 인맥`;},200);}

/* ═══ 인맥 목록 ══════════════════════════════════════════════════ */
let listSort = 'referral'; // 'referral' | 'temp'

function setListSort(s){
  listSort = s;
  document.querySelectorAll('.sort-btn').forEach(b => b.classList.toggle('on', b.dataset.s===s));
  renderList();
}

function renderList(){
  const q=document.getElementById('srchInput').value.trim().toLowerCase();
  let ppl=[...D.people];
  if(q) ppl=ppl.filter(p=>(p.name||'').toLowerCase().includes(q)
                       || groupNameOf(p).toLowerCase().includes(q));

  if(listSort === 'temp'){
    /* 관계온도 낮은 순 */
    ppl.sort((a,b) => calcRelationshipTemp(a).total - calcRelationshipTemp(b).total);
  } else if(listSort === 'group'){
    /* 그룹 순 (동창→직장→가족→기타), 같은 그룹 내 이름 가나다 */
    const order = { alumni:0, work:1, family:2, etc:3 };
    ppl.sort((a,b) => {
      const oa=order[a.rel]??9, ob=order[b.rel]??9;
      if(oa!==ob) return oa-ob;
      /* 기타끼리는 사용자 지정 그룹명으로 */
      const ga=groupNameOf(a), gb=groupNameOf(b);
      if(ga!==gb) return ga.localeCompare(gb,'ko');
      return (a.name||'').localeCompare(b.name||'','ko');
    });
  } else {
    /* 소개 횟수 많은 순 (기본) */
    ppl.sort((a,b) => rc(b.id) - rc(a.id));
  }

  const box=document.getElementById('plist');
  if(!ppl.length){
    box.innerHTML=`<div class="empty"><div class="empty-icon">${q?'🔍':'👥'}</div><p>${q?'검색 결과가 없습니다':'아직 등록된 인맥이 없어요<br>연결망 화면의 + 버튼으로 추가하세요'}</p></div>`;
    return;
  }

  let lastGroup = null;  // 그룹 순일 때 헤더 구분용

  box.innerHTML=ppl.map(p=>{
    const col=REL[p.rel].col, rcN=rc(p.id), hub=isHub(p.id);
    const refP=p.ref?D.people.find(x=>x.id===p.ref):null;
    const t = calcRelationshipTemp(p);

    /* 그룹 순 정렬 시: 그룹이 바뀔 때마다 헤더 삽입 */
    let groupHeader = '';
    if(listSort === 'group'){
      const g = groupNameOf(p);
      if(g !== lastGroup){
        lastGroup = g;
        groupHeader = `<div class="group-header">📁 ${esc(g)}</div>`;
      }
    }

    /* 오른쪽 영역: 정렬 기준에 따라 다르게 표시 */
    const rightHTML = listSort === 'temp'
      ? `<div class="prc">
          <div class="prc-temp-emoji">${t.emoji.split('')[0]}</div>
          <div class="prc-temp-num" style="color:${t.color}">${t.total}°</div>
        </div>`
      : `<div class="prc"><div class="prc-n">${rcN}</div><div class="prc-l">소개</div></div>`;

    /* 그룹 배지 (항상 그룹명 표시) */
    const groupBadge = `<span class="group-badge">📁 ${esc(groupNameOf(p))}</span>`;

    return `${groupHeader}<div class="pcard" onclick="openDetail(${p.id})">
      <div class="pav" style="background:linear-gradient(135deg,${lighten(col)},${col})">${esc((p.name||'?').charAt(0))}</div>
      <div class="pi">
        <div class="pn">${esc(p.name)}${hub?' ⭐':''}<span class="pbadge" style="background:${col}22;color:${col}">${REL[p.rel].sh}</span></div>
        <div class="pm">${refP?esc(refP.name)+' 소개':''}${groupBadge}</div>
      </div>
      ${rightHTML}
    </div>`;
  }).join('');
}
document.getElementById('srchInput').addEventListener('input',renderList);

/* ═══ 연락 알림 ══════════════════════════════════════════════════ */
function buildAlerts(threshold){
  const items=[],seen=new Set();
  D.people.forEach(p=>{
    const d=ago(p.lastContact);
    /* 개인 설정 → 전역 기준일 순으로 적용 (그룹 무관) */
    const thr = threshold ?? p.alertDays ?? alertThreshold ?? 30;
    /* 모든 사람 동일 기준: 접촉 기록 없거나 기준일 경과 시 알림 */
    if(d===null){
      items.push({p,lvl:2,reason:'접촉 기록이 없습니다. 첫 연락을 시작해보세요.'});
    } else if(d>=thr){
      const lvl = d>=thr*3 ? 2 : 1;
      items.push({p,lvl,reason:`마지막 접촉 후 ${d}일 경과 (기준 ${thr}일) — 연락이 필요합니다.`});
    }
  });
  return items
    .filter(it=>{const k=it.p.id+'_'+it.lvl;if(seen.has(k))return false;seen.add(k);return true;})
    .sort((a,b)=>b.lvl-a.lvl || ago(a.p.lastContact??'1900-01-01')-ago(b.p.lastContact??'1900-01-01'));
}

function renderAlerts(){
  syncAlertButtons();               // 저장된 기준일에 맞게 버튼/입력칸 상태 반영
  const thr=alertThreshold;
  const items=buildAlerts(thr),box=document.getElementById('alertBody');
  if(!items.length){
    box.innerHTML=`<div class="empty"><div class="empty-icon">🎉</div><p>기준 <b>${thr}일</b> 이내에 챙길 항목이 없습니다<br>접촉일을 기록하면 알림을 알려드립니다</p></div>`;
    return;
  }
  const urgent=items.filter(i=>i.lvl>0), dead=items.filter(i=>i.lvl===0);
  let html='';
  if(urgent.length){
    html+=`<div class="sec-ttl">🔔 연락 필요 — 기준 ${thr}일 이상 경과 (${urgent.length}명)</div>`;
    html+=urgent.map(it=>{
      const col=REL[it.p.rel].col;
      const d=ago(it.p.lastContact);
      const urgentClass = it.lvl>=2 ? ' urgent' : '';
      return `<div class="acard${urgentClass}">
        <div class="at">
          <span style="width:9px;height:9px;border-radius:50%;background:${col};display:inline-block;flex-shrink:0"></span>
          ${esc(it.p.name)}
          <span style="font-size:11px;color:var(--txt3)">${REL[it.p.rel].sh}</span>
          ${d!==null?`<span style="margin-left:auto;font-size:11px;font-weight:700;color:${it.lvl>=2?'var(--red)':'var(--amber)'}">${Math.max(0,d)}일 경과</span>`:'<span style="margin-left:auto;font-size:11px;color:var(--txt3)">기록 없음</span>'}
        </div>
        <div class="ad">${it.reason}</div>
        <div class="abtn-row">
          <button class="abtn pri" onclick="markContact(${it.p.id})">오늘 접촉함</button>
          <button class="abtn sec" onclick="openDetail(${it.p.id})">상세 보기</button>
        </div>
      </div>`;
    }).join('');
  }
  if(dead.length){
    html+=`<div class="sec-ttl" style="margin-top:16px">🌱 소개 확장 여지 (${dead.length}명)</div>`;
    html+=dead.map(it=>`<div class="acard">
      <div class="at">🌱 ${esc(it.p.name)}</div>
      <div class="ad">${it.reason}</div>
      <div class="abtn-row">
        <button class="abtn pri" onclick="addReferred(${it.p.id})">소개 인맥 추가</button>
        <button class="abtn sec" onclick="openDetail(${it.p.id})">상세 보기</button>
      </div>
    </div>`).join('');
  }
  box.innerHTML=html;
}

/* ─── 알림 필터 버튼 이벤트 ─── */
document.getElementById('alertFilterRow').addEventListener('click', e=>{
  const btn = e.target.closest('.af-btn'); if(!btn) return;
  const customWrap = document.getElementById('afCustomWrap');
  if(btn.dataset.d==='custom'){
    /* 직접입력: 값 확정 전까지는 아직 적용하지 않고 입력칸만 노출 */
    document.querySelectorAll('.af-btn').forEach(b=>b.classList.remove('on'));
    btn.classList.add('on');
    customWrap.classList.remove('hide');
    const inp=document.getElementById('afCustomInput');
    inp.value = inp.value || alertThreshold;   // 현재 값 미리 채움
    inp.focus();
  } else {
    setAlertThreshold(+btn.dataset.d);          // 30일 등 즉시 적용·저장
  }
});
document.getElementById('afApply').addEventListener('click', ()=>{
  const v = parseInt(document.getElementById('afCustomInput').value);
  if(!v||v<1){toast('올바른 일 수를 입력하세요','⚠');return;}
  setAlertThreshold(v);                          // 기본 기준일로 저장 + 실시간 반영
  toast(`기본 기준일이 ${v}일로 설정됐습니다`,'🔔');
});
document.getElementById('afCustomInput').addEventListener('keydown', e=>{
  if(e.key==='Enter') document.getElementById('afApply').click();
});


/* ═══════════════════════════════════════════════════════════
   일정 (SCHEDULE) — localStorage에 사번별 저장
═══════════════════════════════════════════════════════════ */
/* ─── 알림 기준일 설정 ─── */
/* 사번별 저장 키 (세션 emp 기준, PUSH_KEY 패턴과 동일) */
const THR_KEY = 'lm_alert_thr_'+((()=>{try{return JSON.parse(localStorage.getItem(SESSION_KEY)||'{}').emp||'x';}catch{return 'x';}})());
/* 저장된 값 있으면 복원, 없으면 기본 30일 */
let alertThreshold = (()=>{ const v=parseInt(localStorage.getItem(THR_KEY)); return (v && v>0) ? v : 30; })();  // 기본 30일

/* 기준일 변경 + 영속화 + 관계온도 실시간 반영 */
function setAlertThreshold(v){
  alertThreshold = v;
  try{ localStorage.setItem(THR_KEY, String(v)); }catch(e){}
  syncAlertButtons();
  renderAlerts();        // 알림 목록
  renderList();          // 인맥 목록 관계온도
  renderTodayDash();     // 오늘 할 일(온도 기반 추천)
}

/* 현재 alertThreshold 값에 맞게 버튼/입력칸 상태 동기화 */
function syncAlertButtons(){
  const row=document.getElementById('alertFilterRow');
  const customWrap=document.getElementById('afCustomWrap');
  const inp=document.getElementById('afCustomInput');
  if(!row) return;
  row.querySelectorAll('.af-btn').forEach(b=>b.classList.remove('on'));
  const preset=row.querySelector('.af-btn[data-d="'+alertThreshold+'"]');
  if(preset){                      // 30일 등 프리셋과 일치
    preset.classList.add('on');
    if(customWrap) customWrap.classList.add('hide');
  } else {                         // 직접입력 값
    const cb=row.querySelector('.af-btn[data-d="custom"]');
    if(cb) cb.classList.add('on');
    if(customWrap) customWrap.classList.remove('hide');
    if(inp) inp.value = alertThreshold;
  }
}

let SCHEDS = [];   // [{ id, date:'YYYY-MM-DD', time:'HH:MM'|'', title, personId|null, memo }]

/* 고유 일정 id 생성 — Date.now() 동시 생성 충돌 방지 */
function newSchedId(){
  let id = Date.now();
  while(SCHEDS.some(s=>s.id===id)) id++;
  return id;
}

/* saveScheds / loadScheds 는 상단 레이어2 암호화 섹션에 정의됨 */

/* ─── 달력 상태 ─── */
let calYear  = new Date().getFullYear();
let calMonth = new Date().getMonth();   // 0-based
let calSelDate = toDateStr(new Date()); // 'YYYY-MM-DD'
let schedEditId = null;

function toDateStr(d) {
  return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
}
function parseDate(s) { const [y,m,d]=s.split('-').map(Number); return new Date(y,m-1,d); }

/* ─── 달력 렌더링 ─── */
function renderCal() {
  const MONTHS = ['1월','2월','3월','4월','5월','6월','7월','8월','9월','10월','11월','12월'];
  document.getElementById('calMonthLabel').textContent = `${calYear}년 ${MONTHS[calMonth]}`;

  const firstDay = new Date(calYear, calMonth, 1).getDay(); // 0=일
  const lastDate = new Date(calYear, calMonth+1, 0).getDate();
  const prevLast = new Date(calYear, calMonth, 0).getDate();
  const todayStr = toDateStr(new Date());

  const grid = document.getElementById('calGrid');
  grid.innerHTML = '';

  // 이전달 빈칸
  for (let i=0; i<firstDay; i++) {
    const d = prevLast - firstDay + 1 + i;
    const ds = `${calYear}-${String(calMonth).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    grid.appendChild(makeCell(d, ds, true));
  }
  // 이번달
  for (let d=1; d<=lastDate; d++) {
    const ds = `${calYear}-${String(calMonth+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    const cell = makeCell(d, ds, false);
    if (ds===todayStr)    cell.classList.add('today');
    if (ds===calSelDate)  cell.classList.add('selected');
    const dow = new Date(calYear,calMonth,d).getDay();
    if (dow===0) cell.classList.add('sun');
    if (dow===6) cell.classList.add('sat');
    grid.appendChild(cell);
  }
  // 다음달 빈칸
  const filled = firstDay + lastDate;
  const remain = filled % 7 === 0 ? 0 : 7 - (filled % 7);
  for (let i=1; i<=remain; i++) {
    const ds = `${calYear}-${String(calMonth+2).padStart(2,'0')}-${String(i).padStart(2,'0')}`;
    grid.appendChild(makeCell(i, ds, true));
  }

  renderDayScheds(calSelDate);
}

function makeCell(day, dateStr, otherMonth) {
  const cell = document.createElement('div');
  cell.className = 'cal-cell' + (otherMonth?' other-month':'');
  cell.innerHTML = `<div class="cal-day">${day}</div>`;

  // 일정 점
  const dayScheds = SCHEDS.filter(s=>s.date===dateStr);
  if (dayScheds.length) {
    const dots = document.createElement('div');
    dots.className = 'cal-dots';
    dayScheds.slice(0,3).forEach(s=>{
      const dot = document.createElement('div');
      dot.className = 'cal-dot';
      // 관련 인맥 색상 or 브랜드색
      const person = s.personId ? D.people.find(p=>p.id===s.personId) : null;
      dot.style.background = person ? REL[person.rel].col : 'var(--brand)';
      dots.appendChild(dot);
    });
    cell.appendChild(dots);
  }

  cell.addEventListener('click', () => {
    calSelDate = dateStr;
    renderCal();
  });
  return cell;
}

function renderDayScheds(dateStr) {
  const hdr = document.getElementById('calDayHeader');
  const list = document.getElementById('calSchedList');
  const d = parseDate(dateStr);
  const DOW = ['일','월','화','수','목','금','토'];
  const [y,m,day2] = dateStr.split('-').map(Number);
  hdr.innerHTML = `${y}년 ${m}월 ${day2}일 (${DOW[d.getDay()]}) <span>+ 버튼으로 일정 추가</span>`;

  const dayScheds = SCHEDS.filter(s=>s.date===dateStr).sort((a,b)=>(a.time||'99:99').localeCompare(b.time||'99:99'));
  if (!dayScheds.length) {
    list.innerHTML = '<div class="empty"><div class="empty-icon">📅</div><p>이 날 일정이 없습니다<br>오른쪽 위 + 버튼으로 추가하세요</p></div>';
    return;
  }
  list.innerHTML = dayScheds.map(s => {
    const person = s.personId ? D.people.find(p=>p.id===s.personId) : null;
    const st     = (s.purpose !== undefined && s.purpose >= 0) ? PIPELINE_STAGES[s.purpose] : null;

    /* 파이프라인 인라인 체크 */
    let pipeInlineHTML = '';
    if(person){
      const pl = ensurePipeline(person);
      const done = pl.dates.filter(Boolean).length;
      if(done < 4){
        const nextStage = PIPELINE_STAGES[done];
        pipeInlineHTML = `<div class="sched-pipe-row">
          <span class="sched-pipe-label">다음 단계:</span>
          <button class="sched-pipe-btn" onclick="toggleStage(${person.id},${done});renderCal()">
            ${nextStage.icon} ${nextStage.label} 완료 체크
          </button>
        </div>`;
      } else {
        pipeInlineHTML = `<div class="sched-pipe-row"><span class="sched-pipe-done">✅ 파이프라인 완료</span></div>`;
      }
    }

    return `<div class="sched-card">
      <div class="sched-time">${s.time||'—'}</div>
      <div class="sched-info">
        <div class="sched-name">${esc(s.title)}</div>
        ${st ? `<span class="sched-purpose-tag" style="background:${st.col}18;color:${st.col}">${st.icon} ${st.label}</span>` : ''}
        ${person?`<div class="sched-person" onclick="openDetail(${person.id})" style="cursor:pointer">👤 ${esc(person.name)} (${REL[person.rel].sh}) ›</div>`:''}
        ${s.memo?`<div class="sched-memo">📍 ${esc(s.memo)}</div>`:''}
        ${pipeInlineHTML}
      </div>
      <div style="display:flex;flex-direction:column;gap:4px;flex-shrink:0">
        <button class="sched-del" onclick="editSched(${s.id})">✏</button>
        <button class="sched-del" onclick="deleteSched(${s.id})">🗑</button>
      </div>
    </div>`;
  }).join('');
}

/* ─── 일정 추가/수정 폼 ─── */
document.getElementById('btnAddSched').addEventListener('click', () => openSchedForm(null));

/* 일정 유형 토글 */
let schedType = 'meeting'; // 항상 meeting (대면 일정 전용)
let schedPurpose = -1;    // 선택된 파이프라인 단계 (-1=미선택)


function setSchedPurpose(stageIdx){
  schedPurpose = stageIdx;
  document.querySelectorAll('.sched-purpose-btn').forEach(b=>{
    b.classList.toggle('on', +b.dataset.stage === stageIdx);
  });
  const st = PIPELINE_STAGES[stageIdx];
  document.getElementById('schedPurposeHint').textContent =
    st ? `${st.icon} ${st.label} 단계 미팅` : '';
}

/* 인맥 선택 시 파이프라인 단계 자동 반영 */
function onSchedPersonChange(){
  const pid = document.getElementById('sPerson').value;
  if(!pid){ schedPurpose = -1; document.querySelectorAll('.sched-purpose-btn').forEach(b=>b.classList.remove('on')); return; }
  const p = D.people.find(x=>x.id===+pid);
  if(!p) return;
  const pl = ensurePipeline(p);
  const done = pl.dates.filter(Boolean).length;
  /* 다음 단계 자동 선택 (완료 단계가 있으면 그 다음, 없으면 0단계) */
  const nextStage = Math.min(done, 3);
  setSchedPurpose(nextStage);
}

function openSchedForm(editId) {
  schedEditId = editId;
  document.getElementById('schedTitle').textContent = editId ? '일정 수정' : '일정 추가';
  schedType = 'meeting'; // 항상 대면

  // 인맥 목록 채우기
  const sel = document.getElementById('sPerson');
  sel.innerHTML = '<option value="">— 인맥에서 선택 —</option>';
  [...D.people].sort((a,b)=>a.name.localeCompare(b.name,'ko')).forEach(p => {
    sel.innerHTML += `<option value="${p.id}">${esc(p.name)} (${REL[p.rel].sh})</option>`;
  });

  if (editId) {
    const s = SCHEDS.find(x=>x.id===editId);
    if(!s) return;
    document.getElementById('sDate').value = s.date;
    document.getElementById('sTime').value = s.time||'';
    sel.value = s.personId||'';
    document.getElementById('sMemo').value = s.memo||'';
    /* purpose 복원 */
    if(s.purpose !== undefined && s.purpose >= 0){
      setSchedPurpose(s.purpose);
    } else {
      schedPurpose = -1;
      document.querySelectorAll('.sched-purpose-btn').forEach(b=>b.classList.remove('on'));
      document.getElementById('schedPurposeHint').textContent = '미팅 목적을 선택하세요';
    }
  } else {
    document.getElementById('sDate').value = calSelDate;
    document.getElementById('sTime').value = '';
    sel.value = '';
    document.getElementById('sMemo').value = '';
    schedPurpose = -1;
    document.querySelectorAll('.sched-purpose-btn').forEach(b=>b.classList.remove('on'));
    document.getElementById('schedPurposeHint').textContent = '미팅 목적을 선택하세요';
  }
  openSheet('shSched');
}

document.getElementById('btnSchedSave').addEventListener('click', () => {
  const date     = document.getElementById('sDate').value;
  const personId = document.getElementById('sPerson').value ? +document.getElementById('sPerson').value : null;

  if (!date)     { toast('날짜를 선택하세요','⚠'); return; }
  if (!personId) { toast('미팅 대상을 선택하세요','⚠'); return; }
  if (schedPurpose < 0) { toast('미팅 목적을 선택하세요','⚠'); return; }

  /* 민감정보 검사 */
  if(!guardSensitive([{id:'sMemo', label:'장소'}])) return;

  const person = D.people.find(x=>x.id===personId);
  const st     = PIPELINE_STAGES[schedPurpose];
  /* 제목 자동 생성: "이름 · 목적" */
  const autoTitle = person ? `${person.name} · ${st.label}` : st.label;

  const obj = {
    date,
    title:     autoTitle,
    time:      document.getElementById('sTime').value||'',
    personId,
    purpose:   schedPurpose,          // 파이프라인 단계
    memo:      document.getElementById('sMemo').value.trim(), // 장소
    isMeeting: true,                  // 항상 대면
  };

  if (schedEditId) {
    Object.assign(SCHEDS.find(x=>x.id===schedEditId), obj);
    toast('일정 수정 완료','✏');
  } else {
    obj.id = newSchedId();
    SCHEDS.push(obj);
    toast('대면 미팅 추가 완료 🤝');
  }
  calSelDate = date;
  calYear  = +date.slice(0,4);
  calMonth = +date.slice(5,7)-1;
  saveScheds(); renderCal(); renderTodayFull(); closeSheet();
});

function editSched(id)   { openSchedForm(id); }

/* 오늘 할 일 탭에서 일정 추가 — 오늘 날짜 고정 + 대면 미팅 기본 */
function openSchedFormToday(){
  const _n = new Date();
  calSelDate = _n.getFullYear()+'-'+String(_n.getMonth()+1).padStart(2,'0')+'-'+String(_n.getDate()).padStart(2,'0');
  schedType = 'meeting';
  openSchedForm(null);
}
function deleteSched(id) {
  if (!confirm('이 일정을 삭제할까요?')) return;
  SCHEDS = SCHEDS.filter(s=>s.id!==id);
  saveScheds(); renderCal(); renderTodayFull(); toast('일정 삭제','🗑');
}

/* 달력 이전/다음 달 버튼 */
document.getElementById('calPrev').addEventListener('click', () => {
  calMonth--; if(calMonth<0){calMonth=11;calYear--;} renderCal();
});
document.getElementById('calNext').addEventListener('click', () => {
  calMonth++; if(calMonth>11){calMonth=0;calYear++;} renderCal();
});

/* ═══ 내비게이션 ════════════════════════════════════════════════ */
function showMainView(id){
  document.querySelectorAll('.main-view').forEach(v=>v.classList.remove('show'));
  const el=document.getElementById(id);
  if(el) el.classList.add('show');
  /* 연결망 뷰 진입 시: 크기 재계산 + 미배치 노드 배치 */
  if(id==='vMap'){
    setTimeout(()=>{
      resize();
      initPos();   /* POS에 없는 노드만 새로 배치 */
    }, 30);        /* CSS transition 후 clientWidth가 확정되는 시점 */
  }
}
document.querySelectorAll('.nitem').forEach(ni=>{
  ni.addEventListener('click',()=>{
    document.querySelectorAll('.nitem').forEach(n=>n.classList.remove('on'));
    ni.classList.add('on');
    closeAllViews();
    const v=ni.dataset.v;
    if(v==='today'){  showMainView('vToday'); renderTodayFull(); }
    else if(v==='map'){ showMainView('vMap'); }
    else {
      showMainView('vMap'); // 연결망은 뒤에 유지
      if(v==='list'){   document.getElementById('vList').classList.add('show');   renderList(); }
      if(v==='cal'){    document.getElementById('vCal').classList.add('show');    renderCal(); }
      if(v==='alerts'){ document.getElementById('vAlert').classList.add('show'); renderAlerts(); }
    }
  });
});
function closeAllViews(){ document.querySelectorAll('.view').forEach(v=>v.classList.remove('show')); }
function closeView(){
  closeAllViews();
  document.querySelectorAll('.nitem').forEach(n=>n.classList.remove('on'));
  /* 현재 메인뷰 기준으로 탭 복원 */
  const activeMain=document.querySelector('.main-view.show');
  if(activeMain&&activeMain.id==='vMap'){
    document.querySelector('.nitem[data-v="map"]').classList.add('on');
  } else {
    document.querySelector('.nitem[data-v="today"]').classList.add('on');
  }
}

/* ═══ 관계 온도 지수 (Relationship Health Score) ════════════════
   최대 100점 = 접촉 신선도(50) + 소개 기여도(30) + 파이프라인(20)

   ┌─ 1. 접촉 신선도 (0~50점) ─ 마지막 연락이 얼마나 최근인가
   │   • 오늘 연락           → 50점
   │   • 기준일의 절반 이내   → 50→30점 선형 감소
   │   • 기준일 이내         → 30→10점 선형 감소
   │   • 기준일 초과         → 10→0점 (기준일의 2배에서 0)
   │   • 연락 기록 없음       → 0점
   │
   ├─ 2. 소개 기여도 (0~30점) ─ 소개를 몇 명 해줬는가
   │   • 1명당 10점, 최대 3명(30점)
   │
   └─ 3. 파이프라인 (0~20점) ─ 영업 단계가 얼마나 진행됐나
       • 완료 단계 1개당 5점, 4단계 완료 시 20점 만점
═══════════════════════════════════════════════════════════════ */
function calcRelationshipTemp(p){
  let freshScore=0, referScore=0, pipeScore=0;

  /* ── 1) 접촉 신선도 (0~50점) ── */
  const d=ago(p.lastContact);
  const thr=getPersonThr(p);
  if(d===null){
    freshScore=0;                       // 연락 기록 없음
  } else if(d<=0){
    freshScore=50;                      // 오늘(또는 UTC 오차로 음수) → 만점
  } else if(d<=thr*0.5){
    /* 0일~기준절반: 50점 → 30점 선형 */
    const ratio=d/(thr*0.5);            // 0~1
    freshScore=Math.round(50-ratio*20); // 50→30
  } else if(d<=thr){
    /* 기준절반~기준일: 30점 → 10점 선형 */
    const ratio=(d-thr*0.5)/(thr*0.5);  // 0~1
    freshScore=Math.round(30-ratio*20); // 30→10
  } else if(d<=thr*2){
    /* 기준일~기준2배: 10점 → 0점 선형 */
    const ratio=(d-thr)/thr;            // 0~1
    freshScore=Math.round(10-ratio*10); // 10→0
  } else {
    freshScore=0;                       // 기준일 2배 초과
  }
  freshScore=Math.max(0, Math.min(50, freshScore));  // 0~50 clamp

  /* ── 2) 소개 기여도 (0~30점) ── 소개 1명당 10점, 최대 3명 ── */
  const rcN=rc(p.id);
  referScore=Math.min(30, rcN*10);

  /* ── 3) 파이프라인 (0~20점) ── 완료 단계 1개당 5점 ── */
  if(p.pipeline){
    const pl=ensurePipeline(p);
    const done=pl.dates.filter(Boolean).length;  // 0~4
    pipeScore=Math.min(20, done*5);              // 단계당 5점, 4단계=20점
  }

  const total=Math.min(100, freshScore+referScore+pipeScore);
  let emoji='',label='',color='';
  if(total>=80){    emoji='🔥🔥🔥'; label='매우 좋음'; color='#E85A00'; }
  else if(total>=60){emoji='🔥🔥';  label='좋음';     color='#D97706'; }
  else if(total>=40){emoji='🌡';    label='보통';     color='#1A6FD4'; }
  else if(total>=20){emoji='❄';    label='식어가는 중'; color='#9333EA'; }
  else{              emoji='🥶';    label='위험';     color='#DC2626'; }

  return {total,freshScore,referScore,pipeScore,emoji,label,color};
}

function renderTempHTML(t){
  return `<div class="temp-box">
    <div class="temp-row">
      <span class="temp-emoji">${t.emoji}</span>
      <div class="temp-info">
        <div class="temp-label">관계 온도 <span style="color:${t.color};font-weight:700">${t.label}</span></div>
        <div class="temp-score-row">
          <span title="마지막 연락이 최근일수록 높음">접촉 ${t.freshScore}/50</span>
          <span title="소개 1명당 10점">소개 ${t.referScore}/30</span>
          <span title="파이프라인 단계당 5점">단계 ${t.pipeScore}/20</span>
        </div>
      </div>
      <div class="temp-total" style="color:${t.color}">${t.total}</div>
    </div>
    <div class="temp-bar-wrap">
      <div class="temp-bar-fill" style="width:${t.total}%;background:${t.color}"></div>
    </div>
  </div>`;
}


/* ─── 첫 실행 온보딩 ─── */
/* ═══ 온보딩 튜토리얼 ══════════════════════════════════════════ */
function checkOnboard(){
  const seen = localStorage.getItem('lm_onboard_seen');
  if(!seen && D.people.length === 0){
    document.getElementById('onboardOverlay').style.display = 'flex';
    obGoTo(1);
  } else {
    document.getElementById('onboardOverlay').style.display = 'none';
  }
}
function obGoTo(n){
  [1,2,3].forEach(i=>{
    const el = document.getElementById('obSlide'+i);
    if(el) el.classList.toggle('hide', i!==n);
  });
}
function skipOnboard(){
  document.getElementById('onboardOverlay').style.display = 'none';
  localStorage.setItem('lm_onboard_seen','1');
  openForm();
}
function startWithSample(){
  document.getElementById('onboardOverlay').style.display = 'none';
  localStorage.setItem('lm_onboard_seen','1');
  loadSample();
  /* 샘플 로드 후 가이드 시작 */
  setTimeout(()=> guideGoTo(1), 400);
}

/* ─── 샘플 튜토리얼 가이드 ─── */
function guideGoTo(n){
  const overlay = document.getElementById('guideOverlay');
  overlay.style.display = 'block';

  /* 모든 step 숨김 */
  [1,2,3,4].forEach(i => {
    const el = document.getElementById('guideStep'+i);
    if(el) el.classList.toggle('hide', i!==n);
  });
  /* 선택 모달도 숨김 */
  document.getElementById('guideExitModal').classList.add('hide');

  /* 가이드 단계별 탭 이동 */
  if(n===1){
    document.querySelector('.nitem[data-v="today"]').click();
  } else if(n===3){
    document.querySelector('.nitem[data-v="map"]').click();
  } else if(n===2 || n===4){
    document.querySelector('.nitem[data-v="today"]').click();
  }
}

/* 건너뛰기 / backdrop 탭 → 선택 모달 표시 */
function guideExit(){
  [1,2,3,4].forEach(i => {
    const el = document.getElementById('guideStep'+i);
    if(el) el.classList.add('hide');
  });
  document.getElementById('guideExitModal').classList.remove('hide');
}

/* 샘플 유지하고 오버레이만 닫기 */
function guideKeepSample(){
  document.getElementById('guideOverlay').style.display = 'none';
  toast('샘플 데이터가 유지됩니다. 설정 → 전체 초기화로 언제든 삭제할 수 있어요.', '💡');
}

/* 취소 — 가이드로 복귀 (마지막으로 보던 단계로) */
function guideExitCancel(){
  /* 어느 단계였는지 기억하지 않으므로 1장으로 복귀 */
  guideGoTo(1);
}

function finishGuide(){
  /* 샘플 데이터 전체 삭제 */
  D = { people:[], nid:1 };
  Object.keys(POS).forEach(k=>delete POS[k]);
  SCHEDS = [];
  saveScheds();
  save(); refresh();

  /* 가이드 닫기 */
  document.getElementById('guideOverlay').style.display = 'none';

  /* 인맥 추가 폼 열기 */
  setTimeout(()=>{
    toast('샘플이 삭제됐습니다. 첫 번째 인맥을 등록해보세요!','✨');
    openForm();
  }, 300);
}

/* ═══ 통계 갱신 ═════════════════════════════════════════════════ */
function refresh(){
  /* 통계 바 제거됨 — 레이아웃만 갱신 */
  relayout();
  document.getElementById('cvHint').style.display=D.people.length?'none':'flex';
  renderTodayDash();
  renderList(); renderAlerts();
}

/* ═══ 소개 예측 점수 (Referral Prediction Score) ══════════════
   "이 고객이 30일 안에 소개해줄 확률"을 0~100%로 계산
   ─────────────────────────────────────────────────────────────
   변수 5개:
   1) 파이프라인 완료 여부 (+35)  : 보험가입까지 완료 → 소개 요청 적기
   2) 최근 접촉 신선도 (+25)     : 최근 접촉일수록 관계 온기 있음
   3) 소개 이력 (+20)            : 과거에 소개한 사람은 또 소개함
   4) 접촉 빈도 추세 (+15)       : 최근 3개월 접촉이 그 전보다 잦으면 상승
   5) 관계 유형 보정 (×0.7~1.0)  : 기존 고객 > 지인 > 신규
════════════════════════════════════════════════════════════════ */
function calcReferralScore(p){
  let score = 0;
  const details = {};

  /* 1) 파이프라인 완료 */
  if(p.pipeline){
    const pl = ensurePipeline(p);
    const done = pl.dates.filter(Boolean).length;
    if(done >= 4){       // 4단계(보험가입) 완료 = 파이프라인 완료
      score += 35; details.pipeline = 35;
    } else if(done >= 2){
      score += 15; details.pipeline = 15;
    } else {
      details.pipeline = 0;
    }
  } else { details.pipeline = 0; }

  /* 2) 최근 접촉 신선도 */
  const d = ago(p.lastContact);
  if(d === null){
    details.fresh = 0;
  } else if(d <= 7){
    score += 25; details.fresh = 25;
  } else if(d <= 14){
    score += 18; details.fresh = 18;
  } else if(d <= 30){
    score += 10; details.fresh = 10;
  } else {
    details.fresh = 0;
  }

  /* 3) 소개 이력 */
  const refCount = rc(p.id);
  if(refCount >= 3){
    score += 20; details.history = 20;
  } else if(refCount >= 1){
    score += 12; details.history = 12;
  } else {
    details.history = 0;
  }

  /* 4) 접촉 빈도 추세 (contactLog 활용) */
  const log = p.contactLog || [];
  const now = Date.now();
  const recent90  = log.filter(l => ago(l.date) !== null && ago(l.date) <= 90).length;
  const prev90    = log.filter(l => { const a=ago(l.date); return a!==null && a>90 && a<=180; }).length;
  if(recent90 > prev90 && recent90 >= 2){
    score += 15; details.trend = 15;
  } else if(recent90 >= 1){
    score += 7; details.trend = 7;
  } else {
    details.trend = 0;
  }

  /* 5) 그룹 보정 — 가족·친척은 소개 부탁이 수월, 나머지는 동일 */
  const GRP_MULT = { family:1.0, alumni:0.95, work:0.95, etc:0.9 };
  const mult = GRP_MULT[p.rel] ?? 0.95;
  score = Math.round(score * mult);
  score = Math.min(98, Math.max(0, score));

  /* 레벨 분류 */
  let level, color, emoji, msg;
  if(score >= 70){
    level='high';   color='#15803D'; emoji='🔥';
    msg='소개 요청하기 딱 좋은 타이밍이에요';
  } else if(score >= 45){
    level='mid';    color='#D97706'; emoji='✨';
    msg='연락하면 소개로 이어질 가능성이 높아요';
  } else if(score >= 20){
    level='low';    color='#1A6FD4'; emoji='💬';
    msg='먼저 관계를 더 쌓아보세요';
  } else {
    level='cold';   color='#9C8878'; emoji='❄️';
    msg='접촉 기록을 쌓으면 예측이 정확해져요';
  }

  return { score, level, color, emoji, msg, details };
}


/* ─── 오늘 할 일 풀뷰 렌더링 (전면 재작성) ─── */
/* 오늘 할 일 — 비대면 연락 추천 + 대면 만남(일정) */

/* 사람별 오늘의 역할 분류 */
function classifyPerson(p){
  const temp = calcRelationshipTemp(p);
  const rs   = calcReferralScore(p);
  const d    = ago(p.lastContact);
  const pl   = ensurePipeline(p);
  const pipelineDone = pl.dates.filter(Boolean).length;

  /* ── 최근 소개 요청 결과 기록 여부 확인 ──
     contactLog에 최근 14일 이내 기록이 있으면
     이미 액션을 취한 것 → 기회 발굴에서 제외 */
  const log = p.contactLog || [];
  const recentlyActed = log.some(l => {
    const daysSince = ago(l.date);
    return daysSince !== null && daysSince <= 14;
  });

  /* ── 기회 발굴 조건 ────────────────────────────────────────────
     조건 충족하더라도, 최근 14일 내 연락+결과 기록한 사람은 제외
  ──────────────────────────────────────────────────────────── */
  if(!recentlyActed){
    /* 1) 파이프라인 4단계(보험가입=완료) + 소개 예측 점수 충분 */
    if(pipelineDone >= 4 && rs.score >= 40){
      return { type:'opportunity', reason: '보험가입 완료 — 소개 요청 드리기 좋은 시점이에요' };
    }

    /* 2) 소개 이력 있음 + 최근 14일 이내 연락 + 온도 양호 */
    if(rc(p.id) >= 1 && d !== null && d <= 14 && temp.total >= 50){
      return { type:'opportunity', reason: '최근 소개 이력 있음 — 다시 한번 부탁드려보세요' };
    }

    /* 3) 관계온도 높고 소개 예측 점수 높음 */
    if(temp.total >= 65 && rs.score >= 50){
      return { type:'opportunity', reason: '관계가 좋을 때 소개 요청 드리면 성공률이 높아요' };
    }
  }

  /* ── 관리 목적 조건 ────────────────────────────────────────────
     오늘 이미 연락한 사람(d===0)은 관리 목적에서도 제외
  ──────────────────────────────────────────────────────────── */
  const thr = getPersonThr(p);
  if(d === 0) return null;  // 오늘 연락 완료 → 할 일 없음

  if(d === null){
    return { type:'manage', reason: '아직 한 번도 연락하지 않았어요 — 첫 연락을 드려보세요' };
  }
  if(temp.total < 35){
    return { type:'manage', reason: `${d}일째 연락이 없어요 — 관계가 식기 전에 안부를 물어보세요` };
  }
  if(d >= thr){
    return { type:'manage', reason: d<=0 ? '오늘 접촉했어요 — 연락을 기록해보세요' : `마지막 연락이 ${d}일 전이에요 — 안부 연락 드릴 시간이에요` };
  }

  return null;
}

/* ── 오늘 스킵한 사람 목록 (당일 비대면 추천에서 제외) ──
   localStorage에 날짜와 함께 저장 → 새로고침/재진입해도 유지, 날짜 바뀌면 초기화 */
let todaySkipped = new Set();
let todaySkipDate = '';
const SKIP_KEY = 'lm_skip';

function loadSkipState(){
  const t = toDateStr(new Date());
  try{
    const raw = localStorage.getItem(SKIP_KEY);
    if(raw){
      const obj = JSON.parse(raw);
      if(obj && obj.date === t && Array.isArray(obj.ids)){
        todaySkipDate = t;
        todaySkipped = new Set(obj.ids);
        return;
      }
    }
  }catch(e){}
  /* 저장된 게 없거나 날짜가 다르면 초기화 */
  todaySkipDate = t;
  todaySkipped = new Set();
  saveSkipState();
}
function saveSkipState(){
  try{
    localStorage.setItem(SKIP_KEY, JSON.stringify({
      date: todaySkipDate,
      ids: [...todaySkipped]
    }));
  }catch(e){}
}
function resetSkipIfNewDay(){
  const t = toDateStr(new Date());
  if(todaySkipDate !== t){
    todaySkipDate = t;
    todaySkipped = new Set();
    saveSkipState();
  }
}
function skipTodayPick(id){
  resetSkipIfNewDay();
  todaySkipped.add(id);
  saveSkipState();
  renderTodayFull();
}

/* ── VIP 판별: 관계 온도 높음 + 소개 다수 + 계약(보험가입) 고객 ── */
function isVipPerson(p){
  const t = calcRelationshipTemp(p);
  const introduced = rc(p.id);                 // 이 사람이 소개한 인원 수
  const pl = p.pipeline ? ensurePipeline(p) : null;
  const contracted = pl ? pl.dates.filter(Boolean).length >= 4 : false;  // 보험가입 완료
  /* 온도 70+ 이거나, 소개 2명 이상이거나, 계약 완료 고객이면 VIP */
  return t.total >= 70 || introduced >= 2 || contracted;
}

/* 오늘 할 일 — 비대면 연락 추천 + 대면 만남(일정) */
function renderTodayFull(){
  resetSkipIfNewDay();
  const hdrEl = document.getElementById('todayDateHdr');
  if(hdrEl){
    const now = new Date();
    const DOW = ['일','월','화','수','목','금','토'];
    hdrEl.innerHTML = `
      <div class="today-date-main">${now.getMonth()+1}월 ${now.getDate()}일 (${DOW[now.getDay()]})</div>
      <div class="today-date-sub">${D.people.length ? '오늘 연락·만남을 확인하세요' : '먼저 인맥을 추가해보세요'}</div>`;
  }

  const heroBox = document.getElementById('todayHero');
  const dashBox = document.getElementById('todayDash');
  if(heroBox) heroBox.innerHTML = '';
  if(!dashBox) return;

  if(!D.people.length){
    dashBox.innerHTML = `<div class="tl-empty">
      <div class="tl-empty-ic">👥</div>
      <div class="tl-empty-msg">아직 등록된 인맥이 없어요</div>
      <button class="btn btn-primary" onclick="openForm()">＋ 인맥 추가하기</button>
    </div>`;
    return;
  }

  /* 로컬 날짜 기준 (UTC 아님 — 한국 시간 정확히 반영) */
  const _d = new Date();
  const today = _d.getFullYear()+'-'+String(_d.getMonth()+1).padStart(2,'0')+'-'+String(_d.getDate()).padStart(2,'0');

  /* ── 섹션 A: 대면 만남 — isMeeting이 명시적으로 false가 아닌 모든 일정 ── */
  const meetingScheds = (SCHEDS||[])
    .filter(s => s.date === today && s.isMeeting !== false)
    .sort((a,b) => (a.time||'99:99').localeCompare(b.time||'99:99'));

  /* ── 섹션 B: 비대면 연락 — 관계온도 최하위 3인 추천 (스킵 반영) ── */
  /* 오늘 이미 연락한 사람, 오늘 대면 일정 있는 사람, 스킵한 사람 제외 */
  const meetingPersonIds = new Set(meetingScheds.map(s=>s.personId).filter(Boolean));

  /* ── 섹션 C 먼저 계산: VIP — 온도 높음/소개 다수/계약 고객 (상위 3인) ── */
  const vips = D.people
    .filter(p => isVipPerson(p) && !meetingPersonIds.has(p.id))
    .map(p => ({ p, t: calcRelationshipTemp(p) }))
    .sort((a, b) => b.t.total - a.t.total)
    .slice(0, 3);
  const vipIds = new Set(vips.map(({p}) => p.id));

  /* ── 섹션 B: 비대면 연락 — 관계온도 최하위 3인 추천 (스킵·VIP·대면 제외) ── */
  /* 오늘 이미 연락한 사람, 대면 일정, 스킵한 사람, VIP로 이미 노출된 사람 제외 */
  const picks = D.people
    .map(p => ({ p, t: calcRelationshipTemp(p) }))
    .filter(({ p }) => ago(p.lastContact) !== 0
                    && !meetingPersonIds.has(p.id)
                    && !todaySkipped.has(p.id)
                    && !vipIds.has(p.id))
    .sort((a, b) => a.t.total - b.t.total)
    .slice(0, 3);

  /* ── 기타 일정 (isMeeting===false) ── */
  const otherScheds = (SCHEDS||[])
    .filter(s => s.date === today && s.isMeeting === false)
    .sort((a,b) => (a.time||'').localeCompare(b.time||''));

  let html = '';

  /* ══ 섹션 A: 오늘 대면 만남 ══ */
  html += `<div class="today-section-label meeting-label">
    <span class="today-section-ic">🤝</span>오늘 대면 만남
  </div>`;

  if(meetingScheds.length){
    meetingScheds.forEach(s => {
      const person = s.personId ? D.people.find(p=>p.id===s.personId) : null;
      const t      = person ? calcRelationshipTemp(person) : null;
      const st     = (s.purpose !== undefined && s.purpose >= 0) ? PIPELINE_STAGES[s.purpose] : null;
      const col    = person ? REL[person.rel].col : '#047857';
      const clickTarget = person
        ? `openDetail(${person.id})`
        : `document.querySelector('.nitem[data-v=cal]').click()`;

      html += `<div class="today-meeting-card" onclick="${clickTarget}">
        <div class="today-meeting-top-label">📌 오늘 만날 분</div>
        <div class="today-pick-body">
          <div class="today-pick-av" style="background:linear-gradient(135deg,${lighten(col)},${col})">
            ${esc(((person?.name)||'?').charAt(0))}
          </div>
          <div class="today-pick-info">
            <div class="today-pick-name">
              ${person ? esc(person.name) : '미팅'}
              ${person ? `<span class="pbadge" style="background:${col}22;color:${col};margin-left:8px">${REL[person.rel].sh}</span>` : ''}
            </div>
            <div class="today-meeting-meta">
              ${st ? `<span class="today-meeting-purpose" style="color:${st.col}">${st.icon} ${st.label}</span>` : ''}
              <span class="today-meeting-time-txt">${s.time || '시간 미정'}</span>
            </div>
            <div class="today-pick-hint">${s.memo ? `📍 ${esc(s.memo)}` : '<span style="color:var(--txt3)">장소 미정</span>'}</div>
          </div>
          <div class="today-pick-temp" style="color:${t ? t.color : '#059669'}">
            ${t ? `<div class="today-pick-emoji">${t.emoji.split('')[0]}</div>
            <div class="today-pick-num">${t.total}°</div>` : ''}
          </div>
        </div>
        <div class="today-pick-bar-wrap">
          <div class="today-pick-bar-fill" style="width:${t ? t.total : 0}%;background:${t ? t.color : '#059669'}"></div>
        </div>
      </div>`;
    });
  } else {
    html += `<div class="today-section-empty">
      오늘 예정된 대면 미팅이 없어요
      <button class="today-section-add-btn" onclick="openSchedFormToday()">+ 일정 추가</button>
    </div>`;
  }

  /* ══ 섹션 B: 오늘 비대면 연락 ══ */
  html += `<div class="today-section-label call-label">
    <span class="today-section-ic">📞</span>오늘 비대면 연락
  </div>`;

  if(picks.length){
    picks.forEach(({ p, t }) => {
      const col = REL[p.rel].col;
      const d   = ago(p.lastContact);
      const dayTxt = daysAgoText(d);
      const hint = t.total < 40
        ? '안부 연락을 드려보세요'
        : t.total >= 70
          ? '소개 요청하기 좋은 타이밍이에요'
          : '꾸준히 관계를 유지해보세요';

      html += `<div class="today-pick-card" onclick="openDetail(${p.id})">
        <div class="today-pick-body">
          <div class="today-pick-av" style="background:linear-gradient(135deg,${lighten(col)},${col})">${esc((p.name||'?').charAt(0))}</div>
          <div class="today-pick-info">
            <div class="today-pick-name">${esc(p.name)}<span class="pbadge" style="background:${col}22;color:${col};margin-left:8px">${REL[p.rel].sh}</span></div>
            <div class="today-pick-day">${dayTxt}</div>
            <div class="today-pick-hint">${hint}</div>
          </div>
          <div class="today-pick-temp" style="color:${t.color}">
            <div class="today-pick-emoji">${t.emoji.split('')[0]}</div>
            <div class="today-pick-num">${t.total}°</div>
          </div>
        </div>
        <div class="today-pick-bar-wrap">
          <div class="today-pick-bar-fill" style="width:${t.total}%;background:${t.color}"></div>
        </div>
        <div class="today-pick-btn-row">
          <button class="today-pick-btn" onclick="event.stopPropagation();markContact(${p.id});renderTodayFull()">
            📞 연락했어요
          </button>
          <button class="today-skip-btn" onclick="event.stopPropagation();skipTodayPick(${p.id})">
            건너뛰기
          </button>
        </div>
      </div>`;
    });
  } else {
    html += `<div class="tl-empty" style="padding:20px 24px 8px">
      <div class="tl-empty-ic">🎉</div>
      <div class="tl-empty-msg">오늘 비대면 연락할 분이 없어요!</div>
    </div>`;
  }

  /* ══ 섹션 C: 오늘의 VIP ══ */
  if(vips.length){
    html += `<div class="today-section-label vip-label">
      <span class="today-section-ic">⭐</span>오늘의 VIP
    </div>`;
    vips.forEach(({ p, t }) => {
      const col = REL[p.rel].col;
      const introduced = rc(p.id);
      const badge = introduced >= 2 ? `소개 ${introduced}명`
                  : (t.total >= 70 ? '핵심 고객' : '계약 고객');
      html += `<div class="today-vip-card" onclick="openDetail(${p.id})">
        <div class="today-pick-body">
          <div class="today-pick-av" style="background:linear-gradient(135deg,${lighten(col)},${col})">${esc((p.name||'?').charAt(0))}</div>
          <div class="today-pick-info">
            <div class="today-pick-name">${esc(p.name)}<span class="pbadge vip-pbadge">⭐ ${badge}</span></div>
            <div class="today-pick-hint">꾸준한 관리로 관계를 지켜보세요</div>
          </div>
          <div class="today-pick-temp" style="color:${t.color}">
            <div class="today-pick-emoji">${t.emoji.split('')[0]}</div>
            <div class="today-pick-num">${t.total}°</div>
          </div>
        </div>
      </div>`;
    });
  }

  /* ── 기타 일정 (있을 때만) ── */
  if(otherScheds.length){
    html += `<div class="today-section-label other-label">
      <span class="today-section-ic">📋</span>기타 일정
    </div>`;
    otherScheds.forEach(s => {
      const person = s.personId ? D.people.find(p=>p.id===s.personId) : null;
      html += `<div class="tl-row" onclick="document.querySelector('.nitem[data-v=cal]').click()">
        <div class="tl-time">${s.time||'—'}</div>
        <div class="tl-info">
          <div class="tl-name">${esc(s.title)}</div>
          ${person ? `<div class="tl-reason">${esc(person.name)}님 관련 일정</div>` : ''}
        </div>
        <span class="tl-arr">›</span>
      </div>`;
    });
  }

  dashBox.innerHTML = html;
}



function renderTodayDash(){
  const activeTab = document.querySelector('.nitem.on');
  if(activeTab && activeTab.dataset.v==='today') renderTodayFull();
}


/* ─── 연락 기준일 (전역 관리) ─── */
/* 그룹(동창/직장/가족/기타)과 무관하게 알림설정 탭의 전역 기준일 사용.
   개인별 예외 설정(alertDays)이 있으면 그것 우선. */
const DEFAULT_THR = { alumni:30, work:30, family:30, etc:30 };  // 폴백용(모두 동일)

function getPersonThr(p){
  /* 개인 설정 → 전역 기준일(알림설정) → 폴백 30일 */
  return p.alertDays ?? alertThreshold ?? 30;
}

/* ═══ 내보내기 / 가져오기 ════════════════════════════════════════ */
document.getElementById('btnExport').addEventListener('click',()=>{
  if(!D.people.length){toast('내보낼 데이터가 없습니다','ℹ');return;}
  openSheet('shExport');
});

/* ═══ 레이어5 — 내보내기 보안 헬퍼 ═════════════════════════════
   1) 내보내기 전 보안 경고 확인 팝업
   2) 메모 포함 여부 선택 (민감정보 선택적 제외)
   3) 파일명에 날짜 자동 포함 (내부 관리용 식별)
════════════════════════════════════════════════════════════════ */

/** 내보내기 공통 보안 확인 — false면 중단 */
function confirmExport(format){
  return confirm(
    `📤 ${format} 내보내기\n\n`+
    `⚠ 보안 주의사항\n`+
    `• 파일에 이름·지역·메모가 포함됩니다\n`+
    `• 개인 PC의 안전한 환경에서만 내보내세요\n`+
    `• 이메일·메신저로 파일을 공유하지 마세요\n`+
    `• 사용 후 파일을 즉시 삭제하는 것을 권장합니다\n\n`+
    `계속 진행하시겠습니까?`
  );
}

/** 메모 포함 여부 확인 — true면 포함 */
function confirmIncludeMemo(){
  return confirm(
    `📝 메모 포함 여부\n\n`+
    `메모 항목을 파일에 포함할까요?\n\n`+
    `[확인] 포함 — 메모 내용이 그대로 저장됩니다\n`+
    `[취소] 제외 — 메모를 "(제외됨)"으로 마스킹합니다\n\n`+
    `민감한 내용이 메모에 있다면 "취소"를 권장합니다`
  );
}

/* ─── Excel 내보내기 (순수 JS, 외부 라이브러리 없음) ─── */
document.getElementById('btnExportExcel').addEventListener('click',()=>{
  closeSheet();
  /* 레이어5: 보안 확인 */
  if(!confirmExport('Excel')) return;
  const includeMemo = confirmIncludeMemo();

  const today = new Date().toISOString().slice(0,10);
  const rows = [
    ['이름/별칭','관계유형','활동지역','소개해준사람','최근접촉일','경과일수','메모','소개수','허브여부']
  ];
  D.people.forEach(p=>{
    const refP = p.ref ? D.people.find(x=>x.id===p.ref) : null;
    const days = ago(p.lastContact);
    rows.push([
      p.name||'',
      REL[p.rel]?.lbl||'',
      p.region||'',
      refP?refP.name:'직접 인맥',
      p.lastContact||'',
      days!==null?days:'',
      includeMemo ? (p.memo||'') : '(제외됨)',   /* 레이어5: 선택적 마스킹 */
      rc(p.id),
      isHub(p.id)?'O':'',
    ]);
  });

  // XML 스프레드시트 형식 (xlsx 라이브러리 없이 Excel 열리는 XML)
  const escX = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const colWidths = [120,80,120,100,100,70,160,60,60];
  const colTags = colWidths.map(w=>`<Column ss:Width="${w}"/>`).join('');

  const xmlRows = rows.map((row,ri)=>{
    const cells = row.map((cell,ci)=>{
      const val = escX(cell);
      const isNum = ri>0 && (ci===5||ci===7) && val!=='';
      return isNum
        ? `<Cell><Data ss:Type="Number">${val}</Data></Cell>`
        : `<Cell><Data ss:Type="String">${val}</Data></Cell>`;
    }).join('');
    const style = ri===0 ? ' ss:StyleID="Header"' : '';
    return `<Row${style}>${cells}</Row>`;
  }).join('');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
<Styles>
  <Style ss:ID="Header">
    <Font ss:Bold="1" ss:Color="#FFFFFF"/>
    <Interior ss:Color="#E85A00" ss:Pattern="Solid"/>
    <Alignment ss:Horizontal="Center"/>
  </Style>
</Styles>
<Worksheet ss:Name="LinkMap 인맥">
<Table>${colTags}${xmlRows}</Table>
</Worksheet>
</Workbook>`;

  const blob = new Blob(['﻿'+xml], {type:'application/vnd.ms-excel;charset=UTF-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `LinkMap_인맥_${today}.xls`;
  a.click();
  toast('Excel 저장 완료','📊');
});

/* ─── PDF 내보내기 (브라우저 print API) ─── */
document.getElementById('btnExportPdf').addEventListener('click',()=>{
  closeSheet();
  /* 레이어5: 보안 확인 */
  if(!confirmExport('PDF')) return;
  const includeMemo = confirmIncludeMemo();

  const today = new Date().toISOString().slice(0,10);

  const tableRows = D.people.map((p,i)=>{
    const refP = p.ref ? D.people.find(x=>x.id===p.ref) : null;
    const days = ago(p.lastContact);
    const colDot = (REL[normalizeRel(p.rel)]||{col:'#999'}).col;
    const memoCell = includeMemo ? (p.memo||'') : '<span style="color:#9C8878;font-style:italic">(제외됨)</span>';
    return `<tr style="${i%2===0?'background:#FFF8F4':''}">
      <td>${i+1}</td>
      <td><b>${p.name||''}</b>${isHub(p.id)?' ⭐':''}</td>
      <td><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${colDot};margin-right:5px;vertical-align:middle"></span>${REL[p.rel]?.lbl||''}</td>
      <td>${p.region||'—'}</td>
      <td>${refP?refP.name:'직접 인맥'}</td>
      <td>${p.lastContact||'—'}</td>
      <td style="color:${days!==null&&days>=90?'#DC2626':days!==null&&days>=45?'#D97706':'inherit'};font-weight:${days!==null&&days>=45?'700':'400'}">${days!==null?days+'일':'-'}</td>
      <td style="text-align:center;font-weight:700;color:#E85A00">${rc(p.id)}</td>
      <td>${memoCell}</td>
    </tr>`;
  }).join('');

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>LinkMap 인맥 목록 — ${today}</title>
<style>
  @page{size:A4 landscape;margin:15mm}
  body{font-family:'Apple SD Gothic Neo','Malgun Gothic',sans-serif;font-size:11px;color:#1C1410}
  h1{font-size:18px;color:#E85A00;margin:0 0 4px}
  .sub{font-size:11px;color:#9C8878;margin-bottom:16px}
  table{width:100%;border-collapse:collapse;font-size:10.5px}
  th{background:#E85A00;color:#fff;padding:7px 6px;text-align:left;white-space:nowrap}
  td{padding:6px 6px;border-bottom:1px solid #E4D9D0;vertical-align:top}
  .foot{margin-top:12px;font-size:10px;color:#9C8878}
  .warn{background:#FEF2F2;border:1px solid #FECACA;border-radius:6px;padding:8px 12px;margin-bottom:12px;font-size:11px;color:#DC2626}
</style></head><body>
<h1>🔗 LinkMap — 인맥 목록</h1>
<div class="sub">출력일: ${today} &nbsp;|&nbsp; 총 ${D.people.length}명${includeMemo?'':' &nbsp;|&nbsp; 메모 제외됨'}</div>
<div class="warn">⚠ 본 문서는 내부 영업관리 전용 자료입니다. 외부 유출을 금지합니다. 사용 후 즉시 파기하세요.</div>
<table>
<thead><tr><th>#</th><th>이름/별칭</th><th>관계유형</th><th>활동지역</th><th>소개해준사람</th><th>최근접촉일</th><th>경과일</th><th>소개수</th><th>메모</th></tr></thead>
<tbody>${tableRows}</tbody>
</table>
</body></html>`;

  const w = window.open('','_blank','width=900,height=650');
  if(!w){ toast('팝업이 차단됐습니다. 브라우저 주소창 옆 팝업 허용 버튼을 눌러주세요','⚠'); return; }
  w.document.write(html);
  w.document.close();
  setTimeout(()=>{ w.print(); }, 600);
  toast('PDF 인쇄 창 열림','📄');
});

/* ─── JSON 백업 (복원용) ─── */
document.getElementById('btnExportJson').addEventListener('click',()=>{
  closeSheet();
  /* 레이어5: 보안 확인 */
  if(!confirmExport('JSON 백업')) return;

  /* JSON 백업은 평문으로 저장 (복원 목적 — 암호화 키 없이도 복원 가능해야 함)
     단, 파일 자체는 안전한 곳(카카오 나에게 전송 등)에 보관 권장 */
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([JSON.stringify(D,null,2)],{type:'application/json'}));
  a.download=`LinkMap_백업_${new Date().toISOString().slice(0,10)}.json`; a.click();
  localStorage.setItem('lm_last_backup', new Date().toISOString().slice(0,10));
  toast('JSON 백업 완료 — 안전한 곳에 보관하세요','💾');
});
document.getElementById('btnImport').addEventListener('click',()=>document.getElementById('fileIn').click());
document.getElementById('fileIn').addEventListener('change',e=>{
  const f=e.target.files[0]; if(!f) return;
  const r=new FileReader();
  r.onload=ev=>{try{const imp=JSON.parse(ev.target.result);if(!Array.isArray(imp.people))throw 0;if(D.people.length&&!confirm('현재 데이터를 덮어씁니다. 계속할까요?'))return;D=imp;if(!D.nid)D.nid=Math.max(0,...D.people.map(p=>p.id||0))+1;Object.keys(POS).forEach(k=>delete POS[k]);save();refresh();toast('복원 완료','⬆');}catch{toast('파일을 읽을 수 없습니다','⚠');}};
  r.readAsText(f); e.target.value='';
});

/* ═══ 설정 ══════════════════════════════════════════════════════ */
document.getElementById('btnSetting').addEventListener('click', openSettingSheet);

function openSettingSheet(){
  /* 현재 상태 반영 */
  const hasPin = !!localStorage.getItem(pinKey());
  document.getElementById('setPinBtn').textContent =
    hasPin ? '🔓 비밀번호 잠금 해제' : '🔐 비밀번호 잠금 설정';
  document.getElementById('setPinBtn').className =
    hasPin ? 'btn btn-ghost set-pin-off' : 'btn btn-primary';
  openSheet('shSetting');
}

/* 전체 초기화 — 2단계 확인 */
function confirmResetAll(){
  closeSheet();
  setTimeout(()=>{
    if(!confirm('⚠ 전체 초기화\n\n모든 인맥·일정 데이터가 삭제됩니다.\n이 작업은 되돌릴 수 없습니다.\n\n정말 삭제할까요?')) return;
    if(!confirm('마지막 확인입니다.\n\n"확인"을 누르면 모든 데이터가 즉시 삭제됩니다.')) return;
    D={people:[],nid:1};
    Object.keys(POS).forEach(k=>delete POS[k]);
    SCHEDS=[]; saveScheds();
    save(); refresh();
    toast('전체 데이터가 초기화됐습니다','🗑');
  }, 200);
}

/* PIN 해제 확인 */
function confirmClearPin(){
  if(!confirm('비밀번호 잠금을 해제할까요?\n\n해제 후에는 앱 실행 시 비밀번호를 묻지 않습니다.')){
    return;
  }
  localStorage.removeItem(pinKey());
  toast('비밀번호 잠금이 해제됐습니다','🔓');
}
function loadSample(){
  if(D.people.length&&!confirm('샘플을 불러오면 현재 데이터를 덮어씁니다.'))return;
  const t=Date.now(), dago=n=>new Date(t-n*86400000).toISOString().slice(0,10);

  /* 파이프라인 헬퍼 — done: 완료 단계 수(0~4), 각 날짜는 역순으로 계산 */
  const pipe = (done, baseDay=0) => ({
    stage: done - 1,
    dates: [
      done>=1 ? dago(baseDay+done*30+60) : null,  // 고객등록
      done>=2 ? dago(baseDay+done*20+30) : null,  // 보장분석
      done>=3 ? dago(baseDay+done*10+15) : null,  // 가입설계
      done>=4 ? dago(baseDay+5)          : null,  // 보험가입
    ],
    history: done > 0
      ? Array.from({length: done}, (_,i) => ({
          stage: i, date: dago(baseDay + (done-i)*20 + 10),
          action: i===0?'고객등록':i===1?'보장분석':i===2?'가입설계':'보험가입'
        }))
      : [],
  });

  D={nid:12,people:[
    /* ── 허브 고객 — 소개 2명, 보험가입 완료, 오래 연락 없음 ── */
    {id:1, name:'이정훈', rel:'alumni', region:'성남시 분당구',
     ref:null, lastContact:dago(125), memo:'자영업, 자녀 2명',
     pipeline: pipe(4, 90),  // 보험가입 완료
     contactLog:[{date:dago(125),result:'contact'}]},

    /* ── 이정훈 소개 — 보험가입 완료, 최근 연락 ── */
    {id:2, name:'박서연', rel:'alumni', region:'성남시 분당구',
     ref:1, lastContact:dago(18), memo:'이정훈 직장 동료',
     pipeline: pipe(4, 50),  // 보험가입 완료 → 소개 2명 해줌
     contactLog:[{date:dago(18),result:'contact'},{date:dago(35),result:'success'}]},

    /* ── 이정훈 소개 — 보험가입 완료, 연락 뜸함 ── */
    {id:3, name:'최민호', rel:'work', region:'용인시 수지구',
     ref:1, lastContact:dago(98), memo:'',
     pipeline: pipe(4, 70),  // 보험가입 완료
     contactLog:[{date:dago(98),result:'contact'}]},

    /* ── 지인 — 보장분석까지 완료, 가입설계 진행 중 ── */
    {id:4, name:'헬스장 형', rel:'work', region:'성남시 분당구',
     ref:null, lastContact:dago(8), memo:'운동 모임 지인',
     pipeline: pipe(2, 20),  // 보장분석까지, 가입설계 진행 중
     contactLog:[{date:dago(8),result:'contact'},{date:dago(22),result:'contact'}]},

    /* ── 박서연 소개 — 보험가입 완료, 최근 연락 양호 ── */
    {id:5, name:'김지아', rel:'alumni', region:'성남시 분당구',
     ref:2, lastContact:dago(4), memo:'박서연 대학 친구',
     pipeline: pipe(4, 30),  // 보험가입 완료
     contactLog:[{date:dago(4),result:'contact'},{date:dago(20),result:'success'}]},

    /* ── 박서연 소개 — 신규, 미팅 예정 → 고객등록 단계 ── */
    {id:6, name:'정우성', rel:'etc', region:'수원시 영통구',
     ref:2, lastContact:null, memo:'신규, 첫 미팅 예정',
     pipeline: pipe(0),  // 아직 시작 전
     contactLog:[]},

    /* ── 최민호 소개 — 보장분석 완료, 가입설계 단계 ── */
    {id:7, name:'한소희', rel:'work', region:'용인시 수지구',
     ref:3, lastContact:dago(55), memo:'',
     pipeline: pipe(3, 30),  // 가입설계까지 완료, 보험가입 대기
     contactLog:[{date:dago(55),result:'contact'},{date:dago(70),result:'pending'}]},

    /* ── 지인 소개 — 고객등록 완료, 보장분석 진행 중 ── */
    {id:8, name:'대학 후배', rel:'alumni', region:'서울시 강남구',
     ref:4, lastContact:dago(25), memo:'',
     pipeline: pipe(1, 15),  // 고객등록 완료
     contactLog:[{date:dago(25),result:'contact'}]},

    /* ── 김지아 소개 — 신규, 연락 없음 → 고객등록 전 ── */
    {id:9, name:'윤도현', rel:'etc', region:'성남시 분당구',
     ref:5, lastContact:null, memo:'김지아 지인, 연락 예정',
     pipeline: pipe(0),
     contactLog:[]},

    /* ── 한소희 소개 — 보험가입 완료, 오래 연락 없음 ── */
    {id:10, name:'서지원', rel:'family', region:'수원시 영통구',
     ref:7, lastContact:dago(155), memo:'',
     pipeline: pipe(4, 120),  // 보험가입 완료
     contactLog:[{date:dago(155),result:'contact'}]},

    /* ── 박서연 소개 — 보험가입 완료, 한달 전 연락 ── */
    {id:11, name:'이하윤', rel:'family', region:'성남시 분당구',
     ref:2, lastContact:dago(30), memo:'',
     pipeline: pipe(4, 20),  // 보험가입 완료
     contactLog:[{date:dago(30),result:'contact'}]},
  ]};

  Object.keys(POS).forEach(k=>delete POS[k]);

  /* ── 샘플 일정 ── */
  const todayStr = toDateStr(new Date());
  const dstr = n => {
    const d = new Date(); d.setDate(d.getDate()+n);
    return toDateStr(d);
  };

  SCHEDS = [
    /* 오늘 대면 미팅 — 헬스장 형 보장분석 → 가입설계 준비 */
    {
      id: Date.now()+1,
      date: todayStr, time: '14:00',
      title: '헬스장 형 · 가입설계',
      personId: 4, purpose: 2,   // 가입설계
      memo: '분당 카페베네',
      isMeeting: true,
    },
    /* 내일 대면 미팅 — 정우성 첫 미팅 */
    {
      id: Date.now()+2,
      date: dstr(1), time: '11:00',
      title: '정우성 · 고객등록',
      personId: 6, purpose: 0,   // 고객등록
      memo: '수원역 스타벅스',
      isMeeting: true,
    },
    /* 3일 후 — 대학 후배 보장분석 */
    {
      id: Date.now()+3,
      date: dstr(3), time: '15:30',
      title: '대학 후배 · 보장분석',
      personId: 8, purpose: 1,   // 보장분석
      memo: '강남 회사 근처',
      isMeeting: true,
    },
  ];
  saveScheds();

  save(); refresh(); toast('샘플 로드 완료','✨');
}

/* ═══ 비밀번호 잠금 ══════════════════════════════════════════════
   보안: SHA-256 (Web Crypto API) 로 PIN 해시 저장
   — 4자리 1만 가지를 전부 해시해도 역산 불가
   — 기존 단순 hashCode() 취약점 수정
═══════════════════════════════════════════════════════════════ */
let pinIn='',pinMode='check',pinFirst='';

/* SHA-256 해시 → HEX 문자열 반환 (async) */
async function hashP(s){
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode('lm_pin_salt_v2:' + s)   // salt로 레인보우테이블 차단
  );
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function buildPad(){
  const pad=document.getElementById('ppad'); pad.innerHTML='';
  ['1','2','3','4','5','6','7','8','9','⌫','0','✓'].forEach(k=>{
    const b=document.createElement('button');
    b.className='pk'+(k==='⌫'||k==='✓'?' fn':''); b.textContent=k;
    b.addEventListener('click',()=>{
      if(k==='⌫'){pinIn=pinIn.slice(0,-1);drawDots();}
      else if(k==='✓'){submitPin();}
      else if(pinIn.length<4){pinIn+=k;drawDots();if(pinIn.length===4)setTimeout(submitPin,140);}
    });
    pad.appendChild(b);
  });
}
function drawDots(){const d=document.getElementById('pdots');d.innerHTML='';for(let i=0;i<4;i++){const s=document.createElement('div');s.className='pdot'+(i<pinIn.length?' on':'');d.appendChild(s);}}

async function submitPin(){
  if(pinIn.length<4)return;
  const pk=pinKey();
  if(pinMode==='check'){
    const hashed = await hashP(pinIn);
    if(hashed===localStorage.getItem(pk)){
      document.getElementById('lockScreen').classList.add('hide');
    } else {
      pinIn='';drawDots();
      document.getElementById('lockD').textContent='비밀번호가 틀렸습니다. 다시 입력하세요.';
    }
  } else if(pinMode==='set'){
    pinFirst=pinIn;pinIn='';pinMode='confirm';drawDots();
    document.getElementById('lockT').textContent='비밀번호 확인';
    document.getElementById('lockD').textContent='같은 번호를 한 번 더 입력하세요';
  } else {
    if(pinIn===pinFirst){
      const hashed = await hashP(pinIn);
      localStorage.setItem(pk, hashed);
      document.getElementById('lockScreen').classList.add('hide');
      toast('비밀번호 잠금 설정됐습니다 (SHA-256 보호)','🔐');
    } else {
      pinIn='';pinMode='set';pinFirst='';drawDots();
      document.getElementById('lockT').textContent='비밀번호 설정';
      document.getElementById('lockD').textContent='번호가 다릅니다. 다시 설정하세요.';
    }
  }
}
function setupPin(){
  /* 기존 PIN이 구버전(짧은 숫자) 형식이면 자동 초기화 후 재설정 유도 */
  const stored = localStorage.getItem(pinKey());
  if(stored && stored.length < 10){
    localStorage.removeItem(pinKey());
    toast('보안 강화로 비밀번호를 재설정합니다','🔐');
  }
  pinMode='set';pinIn='';pinFirst='';
  document.getElementById('lockT').textContent='비밀번호 설정';
  document.getElementById('lockD').textContent='사용할 4자리 번호를 입력하세요';
  buildPad();drawDots();document.getElementById('lockScreen').classList.remove('hide');
}
function checkLock(){
  if(!localStorage.getItem(pinKey()))return;
  pinMode='check';pinIn='';buildPad();drawDots();
  document.getElementById('lockT').textContent='잠금 해제';
  document.getElementById('lockD').textContent='4자리 비밀번호를 입력하세요';
  document.getElementById('lockScreen').classList.remove('hide');
}

/* ═══ 웹 푸시 알림 ══════════════════════════════════════════════
   Service Worker + Notification API 사용
   GitHub Pages는 HTTPS이므로 SW 등록 가능
   iOS 16.4+ PWA 홈화면 추가 상태에서만 푸시 수신 가능
═══════════════════════════════════════════════════════════════ */
const PUSH_KEY='lm_push_'+( (()=>{try{return JSON.parse(localStorage.getItem(SESSION_KEY)||'{}').emp||'x';}catch{return 'x';}})() );

/* Service Worker 등록 */
async function registerSW(){
  if(!('serviceWorker' in navigator)) return null;
  try{
    const reg=await navigator.serviceWorker.register('sw.js',{scope:'./'});
    return reg;
  }catch(e){ console.warn('SW 등록 실패',e); return null; }
}

/* 알림 권한 요청 + SW 등록 */
async function requestPushPermission(){
  if(!('Notification' in window)){
    toast('이 브라우저는 알림을 지원하지 않습니다','⚠'); return;
  }
  if(Notification.permission==='granted'){
    toast('이미 알림이 허용되어 있습니다','🔔'); 
    localStorage.setItem(PUSH_KEY,'1');
    scheduleDailyCheck();
    return;
  }
  if(Notification.permission==='denied'){
    toast('브라우저 설정에서 알림을 허용해 주세요','⚠'); return;
  }
  const perm=await Notification.requestPermission();
  if(perm==='granted'){
    localStorage.setItem(PUSH_KEY,'1');
    await registerSW();
    scheduleDailyCheck();
    toast('알림이 설정됐습니다! 매일 연락 알림을 받습니다 🔔','✅');
  } else {
    toast('알림 허용을 거부하셨습니다','ℹ');
  }
}

/* 알림 전송 (SW 있으면 SW로, 없으면 Notification 직접) */
async function sendPushNotification(title, body, tag='linkmap'){
  if(Notification.permission!=='granted') return;
  const reg=('serviceWorker' in navigator)?await navigator.serviceWorker.getRegistration('./'):null;
  if(reg&&reg.showNotification){
    await reg.showNotification(title,{
      body, tag, icon:'icon-192.png', badge:'icon-192.png',
      data:{url:'./app.html'},
      vibrate:[200,100,200],
    });
  } else {
    const n=new Notification(title,{body,icon:'icon-192.png',tag});
    n.onclick=()=>{ window.focus(); n.close(); };
  }
}

/* 연락 필요 인원 체크 후 알림 발송 */
async function checkAndNotify(){
  if(Notification.permission!=='granted') return;
  if(!localStorage.getItem(PUSH_KEY)) return;
  const urgent=buildAlerts(alertThreshold).filter(i=>i.lvl>=2);
  const warn  =buildAlerts(alertThreshold).filter(i=>i.lvl===1);
  if(urgent.length){
    const names=urgent.slice(0,3).map(i=>i.p.name).join(', ');
    await sendPushNotification(
      `🚨 긴급 연락 필요 — ${urgent.length}명`,
      `${names}${urgent.length>3?` 외 ${urgent.length-3}명`:''}에게 오늘 바로 연락하세요!`
    );
  } else if(warn.length){
    const names=warn.slice(0,3).map(i=>i.p.name).join(', ');
    await sendPushNotification(
      `🔔 연락 알림 — ${warn.length}명`,
      `${names}${warn.length>3?` 외 ${warn.length-3}명`:''}에게 연락할 타이밍입니다`
    );
  }
}

/* 하루 한 번 체크 스케줄 (앱이 열려있는 동안) */
let _pushTimer=null;
function scheduleDailyCheck(){
  clearInterval(_pushTimer);
  // 즉시 한 번 체크
  setTimeout(checkAndNotify, 3000);
  // 이후 1시간마다 반복 체크 (앱 열린 동안)
  _pushTimer=setInterval(checkAndNotify, 60*60*1000);
}

/* 푸시 버튼 이벤트 */
document.getElementById('btnPush').addEventListener('click', async ()=>{
  const isOn=localStorage.getItem(PUSH_KEY)==='1'&&Notification.permission==='granted';
  if(isOn){
    if(confirm('푸시 알림을 끄시겠습니까?')){
      localStorage.removeItem(PUSH_KEY);
      clearInterval(_pushTimer);
      toast('알림이 꺼졌습니다','🔕');
      document.getElementById('btnPush').textContent='🔔';
    }
  } else {
    await requestPushPermission();
  }
  updatePushBtn();
});

function updatePushBtn(){
  const isOn=localStorage.getItem(PUSH_KEY)==='1'&&Notification.permission==='granted';
  const btn=document.getElementById('btnPush');
  btn.textContent = isOn ? '🔕' : '🔔';
  btn.title       = isOn ? '푸시 알림 끄기' : '푸시 알림 설정';
  btn.style.background = isOn ? 'var(--brand)' : '';
  btn.style.color      = isOn ? '#fff' : '';
}

/* ═══ 초기화 ════════════════════════════════════════════════════ */
async function init(){
  try{
    const s=localStorage.getItem(SESSION_KEY);
    if(!s){window.location.href='index.html';return;}
    user=JSON.parse(s);
  }catch(e){window.location.href='index.html';return;}
  await load();
  await loadScheds();
  loadSkipState();  /* 오늘 스킵 상태 복원 (새로고침 대응) */
  resize(); relayout(); loop(); checkLock();
  refresh();
  checkOnboard();
  window.addEventListener('resize',resize);
  registerSW();
  updatePushBtn();
  if(localStorage.getItem(PUSH_KEY)==='1'&&Notification.permission==='granted'){
    scheduleDailyCheck();
  }
  checkBackupReminder();
  /* 앱이 다시 보일 때(백그라운드→포그라운드) 날짜 바뀌었으면 오늘 할 일 갱신 */
  document.addEventListener('visibilitychange', ()=>{
    if(!document.hidden){
      const t = toDateStr(new Date());
      if(todaySkipDate !== t){
        resetSkipIfNewDay();
        const activeTab = document.querySelector('.nitem.on');
        if(activeTab && activeTab.dataset.v==='today') renderTodayFull();
      }
    }
  });
  /* 첫 화면 = 오늘 할 일 */
  showMainView('vToday');
  renderTodayFull();
}

function checkBackupReminder(){
  const last=localStorage.getItem('lm_last_backup');
  if(!last) return;
  const daysSince=Math.floor((Date.now()-new Date(last))/86400000);
  if(daysSince>=30){
    setTimeout(()=>toast(`마지막 백업이 ${daysSince}일 전입니다 — ⬇ 버튼으로 백업하세요`,'💾'),3000);
  }
}

init();
