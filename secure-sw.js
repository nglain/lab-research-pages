'use strict';
const ROOT=new URL('./',self.location.href), encoder=new TextEncoder(), dbName='lab-encrypted-pages:'+ROOT.pathname;
let configPromise,manifestPromise,sessionPromise,assistantPromise;
const freshConfig=()=>fetch(new URL('_gate/config.json',ROOT),{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('config');return r.json();});
const config=()=>configPromise??=freshConfig().catch(error=>{configPromise=null;throw error;});
const keyScope=c=>`${c.version}:${c.salt}:${c.iterations}`;
async function storage(action,value){
  const db=await new Promise((resolve,reject)=>{const r=indexedDB.open(dbName,1);r.onupgradeneeded=()=>r.result.createObjectStore('session');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
  try{return await new Promise((resolve,reject)=>{const tx=db.transaction('session',action==='get'?'readonly':'readwrite'), store=tx.objectStore('session');const r=action==='get'?store.get('active'):action==='put'?store.put(value,'active'):store.delete('active');let result;r.onsuccess=()=>{result=r.result;};tx.oncomplete=()=>resolve(result);tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error);});}finally{db.close();}
}
const decrypt=(key,data,aad)=>crypto.subtle.decrypt({name:'AES-GCM',iv:data.slice(0,12),additionalData:encoder.encode(aad)},key,data.slice(12));
async function readManifest(key,c){
  const r=await fetch(new URL(c.manifest,ROOT));if(!r.ok)throw Error('manifest');
  const bytes=new Uint8Array(await r.arrayBuffer());let plain;
  try{plain=await decrypt(key,bytes,'lab-pages-manifest-v1');}catch{throw Error('session_key');}
  return JSON.parse(new TextDecoder().decode(plain));
}
async function session(){
  const c=await config();const s=await (sessionPromise??=storage('get'));
  if(!s||s.expires<=Date.now()||(s.keyScope&&s.keyScope!==keyScope(c)))return null;
  return s;
}
async function currentManifest(s,c){
  const manifest=await (manifestPromise??=readManifest(s.key,c).catch(error=>{manifestPromise=null;throw error;}));
  // Migrate a valid older session without extending its expiry or saving the password.
  if(!s.keyScope){const state={key:s.key,keyScope:keyScope(c),expires:s.expires};await storage('put',state);sessionPromise=Promise.resolve(state);}
  return manifest;
}
async function forgetSession(){await storage('delete');sessionPromise=Promise.resolve(null);manifestPromise=null;assistantPromise=null;}
async function refreshConfig(){
  const latest=await freshConfig(),previous=await config();
  if(latest.build!==previous.build){manifestPromise=null;assistantPromise=null;}
  configPromise=Promise.resolve(latest);return latest;
}
async function lockedResponse(request,headers){
  if(request.mode==='navigate'){const r=await fetch(new URL('_gate/login.html',ROOT),{cache:'no-store'});return new Response(await r.text(),{headers:{...headers,'Content-Type':'text/html; charset=utf-8'}});}
  return new Response('Locked',{status:401,headers});
}
self.addEventListener('install',e=>e.waitUntil(self.skipWaiting()));
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('message',event=>{
  const source=event.source;
  if(!source?.url||!source.url.startsWith(ROOT.href))return;
  const reply=data=>event.ports[0]?.postMessage(data);
  event.waitUntil((async()=>{
    try{
      if(event.data?.type==='unlock'){
        const c=await freshConfig();if(event.data.build!==c.build)throw Error('build');
        const key=await crypto.subtle.importKey('raw',event.data.raw,{name:'AES-GCM'},false,['decrypt']);
        const manifest=await readManifest(key,c);
        const state={key,keyScope:keyScope(c),expires:Date.now()+12*60*60*1000};
        await storage('put',state);configPromise=Promise.resolve(c);manifestPromise=Promise.resolve(manifest);sessionPromise=Promise.resolve(state);assistantPromise=null;await self.clients.claim();reply({ok:true});
      }else if(event.data?.type==='lock'){
        await forgetSession();reply({ok:true});
        const clients=await self.clients.matchAll();for(const client of clients)client.postMessage({type:'locked'});
      }else if(event.data?.type==='status'){
        const c=await refreshConfig(),s=await session();
        if(s)await currentManifest(s,c);
        reply({expires:s?.expires||0});
      }
    }catch(error){if(error.message==='session_key')await forgetSession();reply({ok:false,expires:0});}
  })());
});
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url);
  if(url.origin!==ROOT.origin||!url.pathname.startsWith(ROOT.pathname))return;
  let path;try{path=decodeURIComponent(url.pathname.slice(ROOT.pathname.length));}catch{return;}
  if(path.startsWith('_gate/')||path==='secure-sw.js')return;
  event.respondWith((async()=>{
    const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'};
    try{
      if(event.request.mode==='navigate')await refreshConfig();
      const s=await session();
      if(!s)return lockedResponse(event.request,headers);
      const c=await config(),manifest=await currentManifest(s,c);
      // Protected API: assistant, semantic search, agent journal and the shared notebook share one login key.
      const apiMethods=path==='api/assistant/status'?['GET']:path==='api/assistant'||path==='api/search'?['POST']:path==='api/agents'?['GET','POST']:path==='api/notes'?['GET','POST']:/^api\/notes\/[0-9a-f-]{36}$/.test(path)?['PUT']:/^api\/notes\/[0-9a-f-]{36}\/comments$/.test(path)?['POST']:/^api\/notes\/[0-9a-f-]{36}\/comments\/[0-9a-f-]{36}$/.test(path)?['PUT','DELETE']:null;
      if(apiMethods){
        try{
          const expectedMethod=event.request.method;
          if(!apiMethods.includes(expectedMethod))return Response.json({error:'Метод недоступен.'},{status:405,headers});
          const configPath='assets/assistant/runtime.json',entry=manifest.files[configPath];
          if(!entry)return Response.json({connected:false,mode:'search-only',error:'Модель пока не подключена.'},{status:path.endsWith('/status')?200:503,headers});
          const runtime=await (assistantPromise??=(async()=>{
            const r=await fetch(new URL(entry.object,ROOT));if(!r.ok)throw Error('runtime');
            return JSON.parse(new TextDecoder().decode(await decrypt(s.key,new Uint8Array(await r.arrayBuffer()),configPath)));
          })());
          const endpoint=new URL(runtime.endpoint);
          if(endpoint.protocol!=='https:'||!endpoint.hostname.endsWith('.workers.dev')||endpoint.username||endpoint.password||!(/^[A-Za-z0-9_-]{43}$/).test(runtime.token))throw Error('runtime');
          endpoint.pathname='/'+path;endpoint.search=path==='api/agents'?url.search:'';endpoint.hash='';
          const response=await fetch(endpoint,{method:expectedMethod,mode:'cors',credentials:'omit',headers:{'Authorization':'Bearer '+runtime.token,'Content-Type':'application/json'},body:['GET','DELETE'].includes(expectedMethod)?undefined:await event.request.text(),signal:AbortSignal.timeout(55000)});
          return new Response(await response.text(),{status:response.status,headers:{...headers,'Content-Type':'application/json; charset=utf-8'}});
        }catch{assistantPromise=null;return Response.json({connected:false,error:'Модель временно недоступна. Разделы доступны по кнопкам.'},{status:503,headers});}
      }
      if(!['GET','HEAD'].includes(event.request.method))return new Response('Method not allowed',{status:405,headers});
      const item=manifest.files[path||'index.html'];
      if(!item)return new Response('Не найдено',{status:404,headers});
      const response=await fetch(new URL(item.object,ROOT));if(!response.ok)throw Error('asset');
      const plain=await decrypt(s.key,new Uint8Array(await response.arrayBuffer()),path||'index.html');
      return new Response(event.request.method==='HEAD'?null:plain,{headers:{...headers,'Content-Type':item.type}});
    }catch(error){
      if(error.message==='session_key'){await forgetSession();return lockedResponse(event.request,headers);}
      return new Response('Не удалось загрузить материал. Обновите страницу.',{status:503,headers});
    }
  })());
});
