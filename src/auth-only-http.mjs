import https from 'node:https';
import dns from 'node:dns';
import { performance } from 'node:perf_hooks';
import { epsXHash } from './signing.mjs';
import { validateEpsRequest } from './request-contract.mjs';

export const AUTH_ONLY_ENDPOINT = 'https://sandboxpgapi.eps.com.bd/v1/Auth/GetToken';
const validSecret = value => typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\x00-\x1f\x7f]/.test(value);
const fail = (code,details={}) => { const error=new Error(code);error.code=code;
  error.failureStage=details.failureStage;error.requestDisposition=details.requestDisposition;error.timing=details.timing;return error; };

function createExchange({hostname='sandboxpgapi.eps.com.bd',port=443,lookup=dns.lookup,ca,servername,
  timeoutMs=20000,maxResponseBytes=32768,localTest=false}={}) {
  let used=false;
  return async credentials => {
    if(used)throw fail('AUTH_ONLY_RETRY_FORBIDDEN'); used=true;
    if(!credentials||![credentials.username,credentials.password,credentials.hashKey].every(validSecret))throw fail('AUTH_ONLY_CREDENTIAL_INPUT_INVALID');
    const body=JSON.stringify({userName:credentials.username,password:credentials.password});
    const request={method:'POST',url:AUTH_ONLY_ENDPOINT,headers:{'Content-Type':'application/json','x-hash':epsXHash(credentials.username,credentials.hashKey)},body};
    if(!validateEpsRequest('AUTH',request,{hashKey:credentials.hashKey}).accepted)throw fail('AUTH_ONLY_REQUEST_CONTRACT_REJECTED');
    if(!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>20000||!Number.isInteger(maxResponseBytes)||maxResponseBytes<1024||maxResponseBytes>32768)throw fail('AUTH_ONLY_LIMITS_INVALID');
    return new Promise((resolve,reject)=>{
      const start=performance.now();let dnsStart=null,dnsEnd=null,tcp=null,tls=null,first=null,settled=false,bytes=0;
      let failureStage='REQUEST_PREPARATION',requestDisposition='NOT_SENT';
      const timing=()=>({dnsMs:dnsStart===null||dnsEnd===null?null:dnsEnd-dnsStart,tcpConnectMs:tcp===null?null:tcp-start,
        tlsHandshakeMs:tcp===null||tls===null?null:tls-tcp,firstByteMs:first===null?null:first-start,
        totalMs:performance.now()-start,tlsVerified:tls!==null,source:localTest?'auth-only-local-tls':'auth-only-sandbox'});
      let timer=null,req;
      const finish=(error,value)=>{if(settled)return;settled=true;if(timer)clearTimeout(timer);const measured=timing();
        error?reject(fail(error,{failureStage,requestDisposition,timing:measured})):
          resolve({...value,timing:measured,requestDisposition:'SENT'});};
      const measuredLookup=(name,options,callback)=>{failureStage='DNS';dnsStart=performance.now();lookup(name,options,(error,address,family)=>{
        dnsEnd=performance.now();if(!error)failureStage='TCP';callback(error,address,family);});};
      try {
        req=https.request({protocol:'https:',hostname,port,path:'/v1/Auth/GetToken',method:'POST',headers:request.headers,
          agent:false,lookup:measuredLookup,ca,servername,rejectUnauthorized:true,minVersion:'TLSv1.2'},res=>{
          requestDisposition='SENT';failureStage='HTTP_RESPONSE';first=performance.now();const chunks=[];
          res.on('data',chunk=>{bytes+=chunk.length;if(bytes>maxResponseBytes){finish('AUTH_ONLY_RESPONSE_SIZE_LIMIT');res.destroy();req.destroy();}else chunks.push(chunk);});
          res.on('end',()=>finish(null,{httpStatus:res.statusCode,body:Buffer.concat(chunks).toString('utf8')}));
          res.on('aborted',()=>finish('AUTH_ONLY_RESPONSE_ABORTED'));res.on('error',()=>finish('AUTH_ONLY_RESPONSE_ABORTED'));
        });
        timer=setTimeout(()=>{finish('AUTH_ONLY_HTTP_TIMEOUT');req.destroy();},timeoutMs);
        req.on('socket',socket=>{socket.once('connect',()=>{tcp=performance.now();failureStage='TLS';if(localTest&&socket.remoteAddress!=='127.0.0.1'){finish('AUTH_ONLY_LOCAL_DESTINATION_REJECTED');req.destroy();}});
          socket.once('secureConnect',()=>{if(!socket.authorized){finish('AUTH_ONLY_TLS_VALIDATION_FAILED');req.destroy();}else{tls=performance.now();failureStage='HTTP_RESPONSE';}});});
        req.on('upgrade',(res,socket)=>{requestDisposition='SENT';failureStage='HTTP_RESPONSE';first=performance.now();finish(null,{httpStatus:res.statusCode,body:''});socket.destroy();});
        req.on('error',()=>finish('AUTH_ONLY_TRANSPORT_FAILURE'));
        requestDisposition='UNCERTAIN';failureStage='DNS';req.end(body);
      } catch {
        failureStage='REQUEST_PREPARATION';requestDisposition='NOT_SENT';finish('AUTH_ONLY_TRANSPORT_FAILURE');
      }
    });
  };
}

export function createAuthOnlySandboxExchange() { return createExchange(); }
export function createLocalAuthOnlyExchange({port,ca,timeoutMs=1000,maxResponseBytes=32768}={}) {
  if(!Number.isInteger(port)||port<1||port>65535||!ca)throw fail('AUTH_ONLY_LOCAL_HARNESS_INVALID');
  const lookup=(_name,options,callback)=>queueMicrotask(()=>options?.all?callback(null,[{address:'127.0.0.1',family:4}]):callback(null,'127.0.0.1',4));
  return createExchange({hostname:'sandboxpgapi.eps.com.bd',port,lookup,ca,servername:'127.0.0.1',timeoutMs,maxResponseBytes,localTest:true});
}
