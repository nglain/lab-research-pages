(()=>{
  const button=document.createElement('button');button.className='icon-button';button.type='button';button.textContent='↪';button.title='Выйти из лаборатории';button.setAttribute('aria-label','Выйти из лаборатории');
  document.querySelector('.app-header')?.append(button);
  const base=new URL('../',document.currentScript.src);
  navigator.serviceWorker.register(new URL('secure-sw.js',base),{scope:base.pathname,updateViaCache:'none'}).catch(()=>{});
  const lock=()=>new Promise(resolve=>{const worker=navigator.serviceWorker.controller;if(!worker)return resolve();const channel=new MessageChannel();channel.port1.onmessage=()=>resolve();worker.postMessage({type:'lock'},[channel.port2]);setTimeout(resolve,3000);});
  button.onclick=async()=>{button.disabled=true;await lock();location.replace(base.href);};
  navigator.serviceWorker.addEventListener('message',e=>{if(e.data?.type==='locked')location.replace(base.href);});
  const channel=new MessageChannel();channel.port1.onmessage=e=>{if(e.data?.expires)setTimeout(()=>location.reload(),Math.max(0,e.data.expires-Date.now()));};
  navigator.serviceWorker.controller?.postMessage({type:'status'},[channel.port2]);
  addEventListener('pageshow',event=>{if(event.persisted)location.reload();});
})();
