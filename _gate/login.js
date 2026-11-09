const base=new URL('../',import.meta.url), form=document.querySelector('form'), input=document.querySelector('#password'), button=form.querySelector('button'), status=document.querySelector('.status');
const tell=(worker,message)=>new Promise((resolve,reject)=>{const channel=new MessageChannel();const timer=setTimeout(()=>reject(Error('timeout')),15000);channel.port1.onmessage=e=>{clearTimeout(timer);channel.port1.close();resolve(e.data);};worker.postMessage(message,[channel.port2]);});
let submitted=false,opening=false;
async function readyWorker(){
  if(!isSecureContext||!navigator.serviceWorker||!crypto.subtle)throw Error('unsupported');
  const registration=await navigator.serviceWorker.register(new URL('secure-sw.js',base),{scope:base.pathname,updateViaCache:'none'});
  await navigator.serviceWorker.ready;
  const worker=registration.active||navigator.serviceWorker.controller;
  if(!worker)throw Error('network');return worker;
}
async function openDocument(){
  if(!navigator.serviceWorker.controller)await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>reject(Error('timeout')),10000);navigator.serviceWorker.addEventListener('controllerchange',()=>{clearTimeout(timeout);resolve();},{once:true});});
  if(location.pathname===base.pathname+'_gate/login.html')location.replace(base.href+location.hash);
  else location.reload();
}
// A restored tab can receive the static gate before its worker controls the page.
// Ask the worker to verify its saved key; never keep the password in browser storage.
async function resumeSavedSession(){try{
  if(submitted||opening)return;
  const saved=await tell(await readyWorker(),{type:'status'});
  if(!submitted&&!opening&&saved.expires>Date.now()){
    opening=true;button.disabled=true;status.textContent='Открываем материалы…';await openDocument();
  }
}catch{opening=false;}}
navigator.serviceWorker?.addEventListener?.('controllerchange',resumeSavedSession);
resumeSavedSession();
form.addEventListener('submit',async e=>{
  e.preventDefault();submitted=true;button.disabled=true;status.textContent='Открываем материалы…';
  try{
    if(!isSecureContext||!navigator.serviceWorker||!crypto.subtle)throw Error('unsupported');
    const config=await fetch(new URL('_gate/config.json',base),{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('network');return r.json();});
    const salt=Uint8Array.from(atob(config.salt),c=>c.charCodeAt(0));
    const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(input.value),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:config.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},true,['decrypt']);
    const data=new Uint8Array(await fetch(new URL(config.manifest,base),{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('network');return r.arrayBuffer();}));
    try{await crypto.subtle.decrypt({name:'AES-GCM',iv:data.slice(0,12),additionalData:new TextEncoder().encode('lab-pages-manifest-v1')},key,data.slice(12));}catch{throw Error('password');}
    const worker=await readyWorker();
    const raw=await crypto.subtle.exportKey('raw',key);
    const result=await tell(worker,{type:'unlock',raw,build:config.build});
    input.value='';
    if(!result.ok)throw Error('network');
    // A same-URL replace with #route only navigates within this login document.
    // Reload makes the unlocked worker serve the page, preserving its route or file.
    await openDocument();
  }catch(error){status.textContent=error.message==='password'?'Пароль не подошёл. Попробуйте ещё раз.':error.message==='unsupported'?'Откройте сайт в современном браузере по HTTPS.':'Не удалось открыть сайт. Проверьте соединение и попробуйте ещё раз.';button.disabled=false;input.focus();}
});
