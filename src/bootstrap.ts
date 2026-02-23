import type { PolicyConfig } from "./types.js";

export function generateBootstrap(cfg: PolicyConfig): string {
  return `(function(__S_CFG__){
try{
if(globalThis.__SENTINEL_INSTALLED__)return;
globalThis.__SENTINEL_INSTALLED__=true;

var CFG=__S_CFG__||{mode:"audit",deny:{}};
var MODE=CFG.mode||"audit";
var SR=typeof CFG.stackSampleRate==="number"?CFG.stackSampleRate:1;
var DENY=CFG.deny||{};

/* ======== CONTEXT DETECTION ======== */
var ctx=(function(){
  try{
    if(typeof window!=="undefined"&&window.location){
      var d=0;
      try{var w=window;while(w!==w.top&&d<50){d++;w=w.parent;}}catch(e){d=-1;}
      return{kind:d>0||d===-1?"iframe":"main",url:String(window.location.href),depth:d,origin:window.location.origin};
    }
  }catch(e){}
  try{
    if(typeof self!=="undefined"){
      var n=self.constructor?self.constructor.name:"";
      if(n==="ServiceWorkerGlobalScope")return{kind:"service_worker",url:String(self.location.href),depth:0,origin:self.location.origin};
      if(n==="SharedWorkerGlobalScope")return{kind:"shared_worker",url:String(self.location.href),depth:0,origin:self.location.origin};
      if(self.location)return{kind:"worker",url:String(self.location.href),depth:0,origin:self.location.origin};
    }
  }catch(e){}
  return{kind:"unknown",url:"",depth:0,origin:""};
})();

/* ======== EVENT QUEUE + BATCHED FLUSH ======== */
var q=[];var ft=null;var SEQ=0;

function emit(ev){
  ev.ts=new Date().toISOString();ev.context=ctx;ev.seq=SEQ++;
  q.push(ev);
  if(!ft)ft=setTimeout(flush,20);
}

function flush(){
  ft=null;
  var batch=q.splice(0,100);
  for(var i=0;i<batch.length;i++){
    try{console.debug("__AV__|"+JSON.stringify(batch[i]));}catch(e){}
  }
  if(q.length>0)ft=setTimeout(flush,20);
}

function stk(){
  if(Math.random()>SR)return null;
  try{return new Error().stack||null;}catch(e){return null;}
}

/* ======== SAFE SERIALIZATION ======== */
function sv(v){
  if(v==null)return v;var t=typeof v;
  if(t==="string")return v.length>300?v.slice(0,300)+"[...]":v;
  if(t==="number"||t==="boolean")return v;
  if(t==="symbol")return v.toString();
  if(t==="function")return"[Function:"+(v.name||"anon")+"]";
  if(v instanceof RegExp)return v.toString();
  if(v instanceof Date)return v.toISOString();
  if(typeof ArrayBuffer!=="undefined"&&v instanceof ArrayBuffer)return"[ArrayBuffer:"+v.byteLength+"]";
  if(typeof Blob!=="undefined"&&v instanceof Blob)return"[Blob:"+v.size+":"+v.type+"]";
  if(typeof URL!=="undefined"&&v instanceof URL)return v.href;
  if(Array.isArray(v)){try{return v.slice(0,10).map(sv);}catch(e){return"[Array:"+v.length+"]";}}
  try{var j=JSON.stringify(v);return j.length>500?j.slice(0,500)+"[...]":JSON.parse(j);}
  catch(e){return"["+Object.prototype.toString.call(v)+"]";}
}
function sa(args){try{return Array.prototype.map.call(args,sv);}catch(e){return["[args:error]"];}}

/* ======== POLICY ENFORCER ======== */
function deny(flag,api){
  if(MODE!=="lockdown"||!flag)return;
  emit({type:"policy:deny",api:api,action:"blocked",stack:stk()});
  throw new DOMException("Sentinel: "+api+" blocked by policy","NotAllowedError");
}

/* ======== HOOK UTILITIES ======== */
function wM(obj,name,api,intent,df){
  try{
    var orig=obj&&obj[name];
    if(typeof orig!=="function"||orig.__S__)return;
    var w=function(){
      deny(df,api);
      emit({type:"browser:access",action:"call",api:api,intent:intent,args:sa(arguments),stack:stk()});
      try{var r=orig.apply(this,arguments);
        if(r&&typeof r.then==="function"){
          r.then(function(v){emit({type:"browser:access",action:"resolve",api:api,intent:intent});})
           .catch(function(e){emit({type:"browser:access",action:"reject",api:api,intent:intent,error:String(e)});});
        }
        return r;
      }catch(e){emit({type:"browser:access",action:"throw",api:api,intent:intent,error:String(e),stack:stk()});throw e;}
    };
    Object.defineProperty(w,"__S__",{value:true});
    Object.defineProperty(w,"name",{value:name});
    Object.defineProperty(w,"length",{value:orig.length});
    try{Object.defineProperty(obj,name,{value:w,configurable:true,writable:true});}catch(e){}
  }catch(e){}
}

function wG(proto,prop,api,intent){
  try{
    var d=Object.getOwnPropertyDescriptor(proto,prop);
    if(!d||typeof d.get!=="function"||d.get.__S__)return;
    var og=d.get,os=d.set;
    var ng=function(){
      emit({type:"browser:access",action:"get",api:api,intent:intent,stack:stk()});
      return og.call(this);
    };
    Object.defineProperty(ng,"__S__",{value:true});
    var ns=os?function(v){
      emit({type:"browser:access",action:"set",api:api,intent:intent,value:sv(v),stack:stk()});
      return os.call(this,v);
    }:undefined;
    Object.defineProperty(proto,prop,{get:ng,set:ns,enumerable:d.enumerable,configurable:d.configurable});
  }catch(e){}
}

function wC(name,intent,df){
  try{
    var Orig=globalThis[name];
    if(typeof Orig!=="function"||Orig.__S__)return;
    var P=new Proxy(Orig,{
      construct:function(t,a,nt){
        deny(df,name);
        emit({type:"browser:access",action:"construct",api:name,intent:intent,args:sa(a),stack:stk()});
        return Reflect.construct(t,a,nt);
      },
      apply:function(t,th,a){
        deny(df,name);
        emit({type:"browser:access",action:"call",api:name,intent:intent,args:sa(a),stack:stk()});
        return Reflect.apply(t,th,a);
      }
    });
    Object.defineProperty(P,"__S__",{value:true});
    globalThis[name]=P;
  }catch(e){}
}

/* ======== CAPABILITY SNAPSHOT ======== */
(function(){
  var caps={};
  try{
    if(typeof navigator!=="undefined"){
      var keys=["userAgentData","bluetooth","usb","hid","serial","gpu","nfc","mediaDevices","clipboard","storage","credentials","geolocation","locks","wakeLock","permissions","serviceWorker"];
      for(var i=0;i<keys.length;i++){try{caps[keys[i]]=!!navigator[keys[i]];}catch(e){caps[keys[i]]=false;}}
      caps.languages=sv(navigator.languages);
      caps.hardwareConcurrency=navigator.hardwareConcurrency;
      caps.deviceMemory=navigator.deviceMemory;
      caps.maxTouchPoints=navigator.maxTouchPoints;
      caps.webdriver=navigator.webdriver;
      caps.cookieEnabled=navigator.cookieEnabled;
    }
    if(typeof window!=="undefined"){
      caps.screen={w:screen.width,h:screen.height,cd:screen.colorDepth};
      caps.devicePixelRatio=window.devicePixelRatio;
      caps.crossOriginIsolated=window.crossOriginIsolated;
      caps.isSecureContext=window.isSecureContext;
    }
    caps.wasm=typeof WebAssembly!=="undefined";
    caps.sharedArrayBuffer=typeof SharedArrayBuffer!=="undefined";
    caps.webgl=typeof WebGLRenderingContext!=="undefined";
    caps.webgpu=typeof navigator!=="undefined"&&!!navigator.gpu;
  }catch(e){}
  emit({type:"browser:capability",caps:caps});
})();

/* === 1. FINGERPRINTING === */
try{
  wG(Navigator.prototype,"userAgent","navigator.userAgent","fingerprinting");
  wG(Navigator.prototype,"appVersion","navigator.appVersion","fingerprinting");
  wG(Navigator.prototype,"platform","navigator.platform","fingerprinting");
  wG(Navigator.prototype,"vendor","navigator.vendor","fingerprinting");
  wG(Navigator.prototype,"hardwareConcurrency","navigator.hardwareConcurrency","fingerprinting");
  wG(Navigator.prototype,"deviceMemory","navigator.deviceMemory","fingerprinting");
  wG(Navigator.prototype,"language","navigator.language","fingerprinting");
  wG(Navigator.prototype,"languages","navigator.languages","fingerprinting");
  wG(Navigator.prototype,"maxTouchPoints","navigator.maxTouchPoints","fingerprinting");
  wG(Navigator.prototype,"doNotTrack","navigator.doNotTrack","fingerprinting");
  wG(Navigator.prototype,"webdriver","navigator.webdriver","fingerprinting");
  wM(Navigator.prototype,"getBattery","navigator.getBattery","fingerprinting");
  if(typeof navigator!=="undefined"&&navigator.userAgentData){
    wM(Object.getPrototypeOf(navigator.userAgentData),"getHighEntropyValues","navigator.userAgentData.getHighEntropyValues","fingerprinting");
  }
}catch(e){}

/* === 2. CANVAS/WEBGL/AUDIO FINGERPRINTING === */
try{
  if(typeof HTMLCanvasElement!=="undefined"){
    wM(HTMLCanvasElement.prototype,"toDataURL","HTMLCanvasElement.toDataURL","fingerprinting");
    wM(HTMLCanvasElement.prototype,"toBlob","HTMLCanvasElement.toBlob","fingerprinting");
    wM(HTMLCanvasElement.prototype,"getContext","HTMLCanvasElement.getContext","fingerprinting");
  }
  if(typeof CanvasRenderingContext2D!=="undefined"){
    wM(CanvasRenderingContext2D.prototype,"getImageData","CanvasRenderingContext2D.getImageData","fingerprinting");
    wM(CanvasRenderingContext2D.prototype,"measureText","CanvasRenderingContext2D.measureText","fingerprinting");
    wM(CanvasRenderingContext2D.prototype,"fillText","CanvasRenderingContext2D.fillText","fingerprinting");
  }
  if(typeof WebGLRenderingContext!=="undefined"){
    wM(WebGLRenderingContext.prototype,"getParameter","WebGLRenderingContext.getParameter","fingerprinting");
    wM(WebGLRenderingContext.prototype,"getExtension","WebGLRenderingContext.getExtension","fingerprinting");
    wM(WebGLRenderingContext.prototype,"getSupportedExtensions","WebGLRenderingContext.getSupportedExtensions","fingerprinting");
  }
  if(typeof WebGL2RenderingContext!=="undefined"){
    wM(WebGL2RenderingContext.prototype,"getParameter","WebGL2RenderingContext.getParameter","fingerprinting");
  }
  wC("AudioContext","fingerprinting");
  wC("OfflineAudioContext","fingerprinting");
}catch(e){}

/* === 3. SCREEN === */
try{
  if(typeof Screen!=="undefined"){
    wG(Screen.prototype,"width","screen.width","fingerprinting");
    wG(Screen.prototype,"height","screen.height","fingerprinting");
    wG(Screen.prototype,"colorDepth","screen.colorDepth","fingerprinting");
    wG(Screen.prototype,"availWidth","screen.availWidth","fingerprinting");
    wG(Screen.prototype,"availHeight","screen.availHeight","fingerprinting");
  }
}catch(e){}

/* === 4. FONTS === */
try{
  if(typeof document!=="undefined"&&document.fonts){
    wM(Object.getPrototypeOf(document.fonts),"check","FontFaceSet.check","fingerprinting");
    wM(Object.getPrototypeOf(document.fonts),"load","FontFaceSet.load","fingerprinting");
  }
}catch(e){}

/* === 5. PERMISSIONS === */
try{
  if(typeof navigator!=="undefined"&&navigator.permissions)
    wM(Object.getPrototypeOf(navigator.permissions),"query","navigator.permissions.query","permission_check");
  if(typeof Notification!=="undefined")
    wM(Notification,"requestPermission","Notification.requestPermission","permission_request",DENY.notifications);
}catch(e){}

/* === 6. GEOLOCATION === */
try{
  if(typeof navigator!=="undefined"&&navigator.geolocation){
    var gp=Object.getPrototypeOf(navigator.geolocation);
    wM(gp,"getCurrentPosition","geolocation.getCurrentPosition","location",DENY.geolocation);
    wM(gp,"watchPosition","geolocation.watchPosition","location",DENY.geolocation);
  }
}catch(e){}

/* === 7. MEDIA DEVICES === */
try{
  if(typeof navigator!=="undefined"&&navigator.mediaDevices){
    var md=Object.getPrototypeOf(navigator.mediaDevices);
    wM(md,"enumerateDevices","mediaDevices.enumerateDevices","camera/mic");
    wM(md,"getUserMedia","mediaDevices.getUserMedia","camera/mic",DENY.media);
    wM(md,"getDisplayMedia","mediaDevices.getDisplayMedia","screen_capture",DENY.media);
  }
}catch(e){}

/* === 8. CLIPBOARD === */
try{
  if(typeof navigator!=="undefined"&&navigator.clipboard){
    var cp=Object.getPrototypeOf(navigator.clipboard);
    wM(cp,"readText","clipboard.readText","clipboard",DENY.clipboardRead);
    wM(cp,"read","clipboard.read","clipboard",DENY.clipboardRead);
    wM(cp,"writeText","clipboard.writeText","clipboard");
    wM(cp,"write","clipboard.write","clipboard");
  }
}catch(e){}

/* === 9. FILE PICKERS === */
try{
  wM(globalThis,"showOpenFilePicker","showOpenFilePicker","file_picker",DENY.filePickers);
  wM(globalThis,"showSaveFilePicker","showSaveFilePicker","file_picker",DENY.filePickers);
  wM(globalThis,"showDirectoryPicker","showDirectoryPicker","file_picker",DENY.filePickers);
}catch(e){}

/* === 10. HARDWARE === */
try{
  if(typeof navigator!=="undefined"){
    if(navigator.bluetooth)wM(Object.getPrototypeOf(navigator.bluetooth),"requestDevice","bluetooth.requestDevice","hardware",DENY.hardware);
    if(navigator.usb){wM(Object.getPrototypeOf(navigator.usb),"requestDevice","usb.requestDevice","hardware",DENY.hardware);wM(Object.getPrototypeOf(navigator.usb),"getDevices","usb.getDevices","hardware");}
    if(navigator.hid){wM(Object.getPrototypeOf(navigator.hid),"requestDevice","hid.requestDevice","hardware",DENY.hardware);}
    if(navigator.serial){wM(Object.getPrototypeOf(navigator.serial),"requestPort","serial.requestPort","hardware",DENY.hardware);}
    if(navigator.gpu)wM(Object.getPrototypeOf(navigator.gpu),"requestAdapter","gpu.requestAdapter","hardware");
  }
}catch(e){}

/* === 11. WEBAUTHN === */
try{
  if(typeof navigator!=="undefined"&&navigator.credentials){
    var cr=Object.getPrototypeOf(navigator.credentials);
    wM(cr,"create","credentials.create","webauthn",DENY.webauthn);
    wM(cr,"get","credentials.get","webauthn",DENY.webauthn);
  }
}catch(e){}

/* === 12. PAYMENTS + WEBRTC === */
wC("PaymentRequest","payments",DENY.payments);
wC("RTCPeerConnection","webrtc",DENY.webrtc);

/* === 13. NETWORK === */
try{
  wM(globalThis,"fetch","fetch","network");
  if(typeof navigator!=="undefined")wM(Navigator.prototype,"sendBeacon","navigator.sendBeacon","telemetry");
  if(typeof XMLHttpRequest!=="undefined"){
    wM(XMLHttpRequest.prototype,"open","XMLHttpRequest.open","network");
    wM(XMLHttpRequest.prototype,"send","XMLHttpRequest.send","network");
  }
  wC("WebSocket","network");
  wC("EventSource","network");
}catch(e){}

/* === 14. STORAGE === */
try{
  if(typeof Document!=="undefined")wG(Document.prototype,"cookie","document.cookie","storage");
  if(typeof window!=="undefined"){
    if(window.localStorage){
      var lp=Object.getPrototypeOf(window.localStorage);
      wM(lp,"getItem","localStorage.getItem","storage");
      wM(lp,"setItem","localStorage.setItem","storage");
      wM(lp,"removeItem","localStorage.removeItem","storage");
      wM(lp,"clear","localStorage.clear","storage");
    }
    if(window.sessionStorage){
      var sp=Object.getPrototypeOf(window.sessionStorage);
      wM(sp,"getItem","sessionStorage.getItem","storage");
      wM(sp,"setItem","sessionStorage.setItem","storage");
      wM(sp,"removeItem","sessionStorage.removeItem","storage");
    }
  }
  if(typeof indexedDB!=="undefined"){
    wM(indexedDB,"open","indexedDB.open","storage");
    wM(indexedDB,"deleteDatabase","indexedDB.deleteDatabase","storage");
  }
  if(typeof caches!=="undefined"){
    wM(caches,"open","caches.open","storage");
    wM(caches,"delete","caches.delete","storage");
    wM(caches,"keys","caches.keys","storage");
  }
}catch(e){}

/* === 15. SERVICE WORKER === */
try{
  if(typeof navigator!=="undefined"&&navigator.serviceWorker)
    wM(Object.getPrototypeOf(navigator.serviceWorker),"register","serviceWorker.register","service_worker");
}catch(e){}

/* === 16. SENSORS === */
try{
  wC("Accelerometer","sensor");
  wC("Gyroscope","sensor");
  wC("Magnetometer","sensor");
  wC("AbsoluteOrientationSensor","sensor");
  wC("AmbientLightSensor","sensor");
}catch(e){}

/* === 17. TIMING (side-channel) === */
try{
  if(typeof performance!=="undefined"){
    wM(Performance.prototype,"now","performance.now","timing");
    wM(Performance.prototype,"getEntries","performance.getEntries","timing");
    wM(Performance.prototype,"getEntriesByType","performance.getEntriesByType","timing");
  }
}catch(e){}

/* === 18. WAKE LOCK / FULLSCREEN === */
try{
  if(typeof navigator!=="undefined"&&navigator.wakeLock)
    wM(Object.getPrototypeOf(navigator.wakeLock),"request","wakeLock.request","wake_lock");
  if(typeof Element!=="undefined")
    wM(Element.prototype,"requestFullscreen","element.requestFullscreen","fullscreen");
}catch(e){}

/* ======== COMMS MONITOR ======== */
try{
  if(typeof window!=="undefined"&&window.postMessage){
    var oPM=window.postMessage;
    window.postMessage=function(msg,tgt,tr){
      var sz=null;try{sz=JSON.stringify(msg).length;}catch(e){}
      emit({type:"comms:send",channel:"postMessage",targetOrigin:sv(tgt),size:sz,stack:stk()});
      return oPM.apply(this,arguments);
    };
  }
}catch(e){}

try{
  if(typeof window!=="undefined"){
    window.addEventListener("message",function(ev){
      var sz=null;try{sz=JSON.stringify(ev.data).length;}catch(e){}
      emit({type:"comms:recv",channel:"message",origin:sv(ev.origin),size:sz,sourceIsNull:ev.source===null});
    },true);
  }
}catch(e){}

try{
  if(typeof BroadcastChannel!=="undefined"){
    var OBC=BroadcastChannel;
    globalThis.BroadcastChannel=new Proxy(OBC,{
      construct:function(t,a,nt){
        var nm=a&&a[0]?String(a[0]):"";
        emit({type:"comms:open",channel:"BroadcastChannel",name:sv(nm),stack:stk()});
        var bc=Reflect.construct(t,a,nt);
        var opm=bc.postMessage;
        bc.postMessage=function(msg){
          emit({type:"comms:send",channel:"BroadcastChannel",name:sv(nm),stack:stk()});
          return opm.apply(this,arguments);
        };
        return bc;
      }
    });
  }
}catch(e){}

try{
  if(typeof MessagePort!=="undefined"){
    wM(MessagePort.prototype,"postMessage","MessagePort.postMessage","comms");
  }
  if(typeof MessageChannel!=="undefined"){
    var OMC=MessageChannel;
    globalThis.MessageChannel=new Proxy(OMC,{
      construct:function(t,a,nt){
        emit({type:"comms:open",channel:"MessageChannel",stack:stk()});
        return Reflect.construct(t,a,nt);
      }
    });
  }
}catch(e){}

/* ======== WASM MONITOR ======== */
try{
  if(typeof WebAssembly!=="undefined"){
    var wHook=function(orig,name){
      return function(){
        var bytes=null;try{var a=arguments[0];if(a&&a.byteLength)bytes=a.byteLength;}catch(e){}
        emit({type:"wasm:use",api:name,bytes:bytes,stack:stk()});
        return orig.apply(this,arguments);
      };
    };
    if(WebAssembly.compile)WebAssembly.compile=wHook(WebAssembly.compile,"WebAssembly.compile");
    if(WebAssembly.instantiate)WebAssembly.instantiate=wHook(WebAssembly.instantiate,"WebAssembly.instantiate");
    if(WebAssembly.compileStreaming)WebAssembly.compileStreaming=wHook(WebAssembly.compileStreaming,"WebAssembly.compileStreaming");
    if(WebAssembly.instantiateStreaming)WebAssembly.instantiateStreaming=wHook(WebAssembly.instantiateStreaming,"WebAssembly.instantiateStreaming");
  }
}catch(e){}

/* ======== EVASION DETECTION ======== */
try{
  if(typeof URL!=="undefined"&&URL.createObjectURL){
    var ocou=URL.createObjectURL;
    URL.createObjectURL=function(obj){
      var kind=null,size=null;
      try{kind=obj&&obj.constructor?obj.constructor.name:typeof obj;}catch(e){}
      try{if(obj&&obj.size)size=obj.size;}catch(e){}
      emit({type:"evasion:blob_create",api:"URL.createObjectURL",kind:sv(kind),size:size,stack:stk()});
      return ocou.apply(this,arguments);
    };
  }
  if(typeof URL!=="undefined"&&URL.revokeObjectURL){
    var orou=URL.revokeObjectURL;
    URL.revokeObjectURL=function(url){
      emit({type:"evasion:blob_revoke",url:sv(url)});
      return orou.apply(this,arguments);
    };
  }
}catch(e){}

try{
  if(typeof Blob!=="undefined"){
    var OBlob=Blob;
    globalThis.Blob=new Proxy(OBlob,{
      construct:function(t,a,nt){
        var totalSize=0;
        try{if(a&&a[0]){for(var i=0;i<a[0].length;i++){var p=a[0][i];if(typeof p==="string")totalSize+=p.length;else if(p&&p.byteLength)totalSize+=p.byteLength;}}}catch(e){}
        emit({type:"evasion:blob_construct",size:totalSize,stack:stk()});
        return Reflect.construct(t,a,nt);
      }
    });
  }
}catch(e){}

try{
  if(typeof HTMLIFrameElement!=="undefined"){
    var srcD=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,"src");
    if(srcD&&srcD.set){
      var oSS=srcD.set;
      Object.defineProperty(HTMLIFrameElement.prototype,"src",{
        get:srcD.get,
        set:function(v){
          var isBlob=typeof v==="string"&&v.startsWith("blob:");
          var isData=typeof v==="string"&&v.startsWith("data:");
          emit({type:"frameguard:set_src",value:sv(v),isBlob:isBlob,isData:isData,stack:stk()});
          return oSS.call(this,v);
        },enumerable:srcD.enumerable,configurable:srcD.configurable
      });
    }
    var sdD=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,"srcdoc");
    if(sdD&&sdD.set){
      var oSD=sdD.set;
      Object.defineProperty(HTMLIFrameElement.prototype,"srcdoc",{
        get:sdD.get,
        set:function(v){
          emit({type:"frameguard:set_srcdoc",size:typeof v==="string"?v.length:null,stack:stk()});
          return oSD.call(this,v);
        },enumerable:sdD.enumerable,configurable:sdD.configurable
      });
    }
  }
}catch(e){}

try{
  if(typeof Worker!=="undefined"&&typeof window!=="undefined"){
    var OW=Worker;
    globalThis.Worker=new Proxy(OW,{
      construct:function(t,a,nt){
        var url=String(a[0]||"");
        emit({type:"browser:access",action:"construct",api:"Worker",intent:"worker",url:sv(url),isBlob:url.startsWith("blob:"),isData:url.startsWith("data:"),stack:stk()});
        return Reflect.construct(t,a,nt);
      }
    });
  }
}catch(e){}

try{
  if(typeof SharedWorker!=="undefined"&&typeof window!=="undefined"){
    var OSW=SharedWorker;
    globalThis.SharedWorker=new Proxy(OSW,{
      construct:function(t,a,nt){
        emit({type:"browser:access",action:"construct",api:"SharedWorker",intent:"shared_worker",args:sa(a),stack:stk()});
        return Reflect.construct(t,a,nt);
      }
    });
  }
}catch(e){}

/* ======== MUTATIONOBSERVER: DYNAMIC IFRAME/SCRIPT ======== */
try{
  if(typeof document!=="undefined"&&typeof MutationObserver!=="undefined"){
    var mo=new MutationObserver(function(mutations){
      for(var m=0;m<mutations.length;m++){
        var added=mutations[m].addedNodes;
        for(var n=0;n<added.length;n++){
          var node=added[n];
          if(node.tagName==="IFRAME"){
            var ifr=node;
            var rect=null;try{rect=ifr.getBoundingClientRect();}catch(e){}
            emit({type:"frameguard:iframe_added",
              src:sv(ifr.src||""),hasSrcdoc:!!ifr.srcdoc,
              sandbox:ifr.getAttribute("sandbox"),allow:ifr.getAttribute("allow"),
              hidden:ifr.hidden||(ifr.style&&ifr.style.display==="none"),
              zeroSize:rect?(rect.width===0||rect.height===0):null,
              stack:stk()
            });
          }
          if(node.tagName==="SCRIPT"){
            emit({type:"frameguard:script_added",src:sv(node.src||"[inline]"),async:node.async,defer:node.defer});
          }
        }
      }
    });
    if(document.documentElement){
      mo.observe(document.documentElement,{childList:true,subtree:true});
    }else{
      document.addEventListener("DOMContentLoaded",function(){
        mo.observe(document.documentElement,{childList:true,subtree:true});
      });
    }
  }
}catch(e){}

/* ======== VISIBILITY ======== */
try{
  if(typeof document!=="undefined"){
    wG(Document.prototype,"hidden","document.hidden","visibility");
    wG(Document.prototype,"visibilityState","document.visibilityState","visibility");
    document.addEventListener("visibilitychange",function(){
      emit({type:"browser:visibility_change",hidden:document.hidden,state:document.visibilityState});
    });
  }
}catch(e){}

emit({type:"sentinel:ready",mode:MODE,context_kind:ctx.kind});

}catch(e){
  try{console.debug("__AV__|"+JSON.stringify({ts:new Date().toISOString(),type:"sentinel:init_error",error:String(e)}));}catch(x){}
}
})(` + JSON.stringify(cfg) + `);`;
}
