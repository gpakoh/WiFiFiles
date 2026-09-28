const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function harness(kind) {
  const nodes=new Map(), requests=[], timers=new Map();let timerID=0;
  function node(id) {
    if(!nodes.has(id))nodes.set(id,{id,value:0,textContent:'',innerHTML:'',disabled:false,style:{},files:[],
      dataset:{current:'/dav/internal/',cancelled:'cancelled',networkError:'network',timeoutError:'timeout',timeout:'timeout'},
      classList:{add(){},remove(){}},addEventListener(name,fn){this['on'+name]=fn},insertAdjacentHTML(){},click(){}});
    return nodes.get(id);
  }
  class XHR {
    constructor(){this.upload={};requests.push(this);this.responseText='';this.status=0;}
    open(method,url){this.method=method;this.url=url;}
    setRequestHeader(){}
    send(body){this.body=body;}
    abort(){this.aborted=true;if(this.onabort)this.onabort();}
    getResponseHeader(){return '';}
    respond(status,body=''){this.status=status;this.responseText=body;if(this.onload)this.onload();}
  }
  const sandbox={XMLHttpRequest:XHR,document:{getElementById:node,querySelectorAll(){return []},createElement(){return node('escape')}},
    location:{origin:'http://reader',reload(){}},confirm(){return true},prompt(){return ''},alert(){},
    setTimeout(fn,delay){const id=++timerID;timers.set(id,{fn,delay});return id},clearTimeout(id){timers.delete(id)}};
  let source=fs.readFileSync(path.join(__dirname,'..',kind==='dav'?'webdav_ui.go':'mobile.go'),'utf8');
  if(kind==='dav')source=source.split('<script>')[1].split('</script>')[0];
  else {
    source=source.split('js := fmt.Sprintf(`')[1].split('`, template.JSEscapeString(token)')[0];
    const substitutions=['token','token','Complete','Uploaded','Skipped','Failed','token','"network"','"network"','"network"','"Preparing"','"Only books"'];
    source=source.replace(/%s/g,()=>substitutions.shift());assert.equal(substitutions.length,0);
  }
  vm.runInNewContext(source,sandbox);
  async function settle(){for(let i=0;i<8;i++)await Promise.resolve();}
  function start(files=[{name:'book.epub',size:100,lastModified:1}]) {
    const input=node(kind==='dav'?'files':'book-files');input.files=files;
    if(kind==='dav')return input.onchange();
    node('queue-form').onsubmit({preventDefault(){}});
  }
  function timeout(){const entry=[...timers.entries()].find(([,t])=>t.delay===180000);assert.ok(entry,'idle watchdog armed');timers.delete(entry[0]);entry[1].fn();}
  function finishMobile(){const x=requests.find(x=>x.url.endsWith('/finish'));assert.ok(x,'finish request');x.respond(200);}
  return {node,requests,timers,start,settle,timeout,finishMobile};
}

for(const kind of ['dav','mobile']) {
  test(kind+': abort at 83% releases the queue and allows retry',async()=>{
    const h=harness(kind);h.start();const first=h.requests[0];
    first.upload.onprogress({lengthComputable:true,loaded:83,total:100});
    h.node(kind==='dav'?'cancel-upload':'cancel-button').onclick();await h.settle();
    assert.equal(first.aborted,true);
    if(kind==='mobile')h.finishMobile();
    assert.equal(h.node(kind==='dav'?'choose-files':'start-button').disabled,false);
    h.start();assert.ok(h.requests.some(x=>x!==first&&x.url.includes(kind==='dav'?'book.epub':'/upload?')));
  });
  test(kind+': idle timeout settles once despite late abort/error events',async()=>{
    const h=harness(kind);h.start();const x=h.requests[0];h.timeout();await h.settle();
    const count=h.requests.length;x.onerror();x.onabort();await h.settle();assert.equal(h.requests.length,count);
    if(kind==='mobile')h.finishMobile();
    assert.equal(h.node(kind==='dav'?'choose-files':'start-button').disabled,false);
    assert.equal([...h.timers.values()].filter(t=>t.delay===180000).length,0);
  });
  test(kind+': progress renews the watchdog and a second batch cannot overlap',async()=>{
    const h=harness(kind);h.start();const before=[...h.timers.keys()][0];h.start();assert.equal(h.requests.length,1);
    const x=h.requests[0];x.upload.onprogress({lengthComputable:true,loaded:10,total:100});assert.equal(h.timers.has(before),false);
    x.respond(201,JSON.stringify({status:'uploaded',stored_as:'book.epub',message:'ok'}));await h.settle();
    if(kind==='mobile')h.finishMobile();
    assert.equal(h.node(kind==='dav'?'choose-files':'start-button').disabled,false);
    assert.equal([...h.timers.values()].filter(t=>t.delay===180000).length,0);
  });
}

test('mobile: cancel preserves unsent files for retry and finish timeout releases controls',()=>{
  const h=harness('mobile');h.start([{name:'one.epub',size:1},{name:'two.epub',size:1}]);
  h.node('cancel-button').onclick();
  assert.equal(h.requests.filter(x=>x.url.includes('/upload?')).length,1);
  const finish=h.requests.find(x=>x.url.endsWith('/finish'));finish.ontimeout();
  h.node('retry-button').onclick();assert.equal(h.requests.filter(x=>x.url.includes('/upload?')).length,2);
  h.requests.filter(x=>x.url.includes('/upload?'))[1].respond(200,JSON.stringify({status:'uploaded',stored_as:'one.epub',message:'ok'}));
  assert.equal(h.requests.filter(x=>x.url.includes('/upload?')).length,3);
});

test('mobile: invalid JSON response does not leave the queue pending',()=>{
  const h=harness('mobile');h.start();h.requests[0].respond(200,'null');
  h.finishMobile();assert.equal(h.node('start-button').disabled,false);
  assert.equal(h.node('retry-button').style.display,'block');
});
