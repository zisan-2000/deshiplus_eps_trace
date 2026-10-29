// The only HTTP client/server in this toolkit. Destination is an owned numeric
// loopback listener, never a supplied URL, hostname, proxy or EPS endpoint.
import https from 'node:https';
import fs from 'node:fs';
import { performance } from 'node:perf_hooks';
import { validateEpsRequest } from './request-contract.mjs';
import { ENDPOINTS } from './eps-contract.mjs';
export const MOCK_SCENARIOS = Object.freeze(['success','pending','http101','gateway101','reference-mismatch',
  'amount-mismatch','malformed','oversize','timeout','redirect','auth-failure','initialize-failure','initialize-timeout']);
const transports=new WeakMap();
const token='SYNTHETIC_OPAQUE_AUTH_TOKEN';
const cert=()=>fs.readFileSync(new URL('../tests/fixtures/mock-loopback-cert.pem',import.meta.url));
function response(step,scenario,context) {
  if((step==='STATUS'&&scenario==='timeout')||(step==='INITIALIZE'&&scenario==='initialize-timeout'))return {timeout:true};
  if(step==='AUTH')return {httpStatus:200,body:JSON.stringify(scenario==='auth-failure'?{errorCode:101,errorMessage:'SYNTHETIC_FAILURE'}:{token,errorCode:null,errorMessage:null})};
  if(step==='INITIALIZE')return {httpStatus:200,body:JSON.stringify(scenario==='initialize-failure'?{ErrorCode:101}:{
    RedirectURL:'https://sandbox.eps.com.bd/SYNTHETIC_HOSTED_PAYMENT_NOT_OPENED',TransactionId:'SYNTHETIC_BANK_REFERENCE',ErrorCode:null,ErrorMessage:null})};
  if(scenario==='http101')return {httpStatus:101,body:''};
  if(scenario==='redirect')return {httpStatus:302,body:''};
  if(scenario==='oversize')return {httpStatus:200,body:' '.repeat(32769)};
  if(scenario==='malformed')return {httpStatus:200,body:'{'};
  return {httpStatus:200,body:JSON.stringify({MerchantTransactionId:scenario==='reference-mismatch'?'00000000000000000000000':context.merchantTransactionId,
    TotalAmount:scenario==='amount-mismatch'?'999.00':context.amount,Status:scenario==='pending'?'Pending':'Success',
    ErrorCode:scenario==='gateway101'?101:null,ErrorMessage:null})};
}
function register(kind,scenario,context,exchange,extra={}) {
  if(!MOCK_SCENARIOS.includes(scenario))throw Error('MOCK_SCENARIO_FORBIDDEN');
  const handle=Object.freeze({});
  transports.set(handle,{kind,scenario,context,exchange,hosted:false,counts:{AUTH:0,INITIALIZE:0,STATUS:0},...extra});
  return handle;
}
export function createMemoryMock(context,scenario='success') {
  return register('memory',scenario,context,async step=>{
    const started=performance.now(),value=response(step,scenario,context);
    if(value.timeout)throw Error('MOCK_HTTP_TIMEOUT');
    return {...value,timing:{source:'in-memory-simulation',totalMs:performance.now()-started,dnsPerformed:false,
      tcpConnectMs:null,tlsHandshakeMs:null,firstByteMs:null,tlsVerified:null}};
  });
}
export function mockTransportInfo(handle) {
  const t=transports.get(handle);if(!t)throw Error('MOCK_TRANSPORT_REQUIRED');
  return {kind:t.kind,port:t.port??null,counts:{...t.counts}};
}
export function simulateMockHostedCompletion(handle) {
  const t=transports.get(handle);if(!t)throw Error('MOCK_TRANSPORT_REQUIRED');t.hosted=true;
}
export async function exchangeMock(handle,step,request) {
  const t=transports.get(handle);if(!t)throw Error('MOCK_TRANSPORT_REQUIRED');
  const valid=validateEpsRequest(step,request,t.context);if(!valid.accepted)throw Error('MOCK_REQUEST_CONTRACT_REJECTED');
  if(step==='STATUS'&&!t.hosted)throw Error('MOCK_HOSTED_COMPLETION_REQUIRED');
  if(t.counts[step]>0)throw Error('MOCK_AUTOMATIC_RETRY_FORBIDDEN');
  t.counts[step]++;
  const result=await t.exchange(step,request);
  if(step==='AUTH'&&result.httpStatus===200) {
    try{const body=JSON.parse(result.body);if(body.token===token)t.context.token=token;}catch{}
  }
  return result;
}
export async function closeMockTransport(handle) {
  const t=transports.get(handle);if(!t)return;
  try{if(t.close)await t.close();}finally{transports.delete(handle);}
}
export async function createLoopbackTlsMock(context,scenario='success') {
  if(!MOCK_SCENARIOS.includes(scenario))throw Error('MOCK_SCENARIO_FORBIDDEN');
  const key=fs.readFileSync(new URL('../tests/fixtures/mock-loopback-key.pem',import.meta.url));
  const certificate=cert();
  let handle;
  const server=https.createServer({key,cert:certificate,minVersion:'TLSv1.2'},(req,res)=>{
    // Only exact EPS request paths are re-used; they are served locally.
    const step=Object.keys(ENDPOINTS).find(name=>req.url?.split('?')[0]===new URL(ENDPOINTS[name]).pathname);
    if(!step||req.socket.remoteAddress!=='127.0.0.1'){res.writeHead(400);res.end();return;}
    const chunks=[];let bytes=0;
    req.on('data',chunk=>{bytes+=chunk.length;if(bytes>32768)req.destroy();else chunks.push(chunk);});
    req.on('error',()=>{});
    req.on('end',()=>{
      const headers=Object.fromEntries(['content-type','x-hash','authorization'].filter(k=>req.headers[k]!==undefined).map(k=>[k,req.headers[k]]));
      const wire={method:req.method,url:new URL(ENDPOINTS[step]).origin+req.url,headers,
        body:step==='STATUS'?null:Buffer.concat(chunks).toString('utf8')};
      if(!validateEpsRequest(step,wire,context).accepted||(step==='STATUS'&&!transports.get(handle)?.hosted)){res.writeHead(400);res.end();return;}
      const value=response(step,scenario,context);
      if(value.timeout)return;
      if(value.httpStatus===101){res.writeHead(101,{Connection:'Upgrade',Upgrade:'synthetic-mock'});res.flushHeaders();return;}
      res.writeHead(value.httpStatus,{'Content-Type':'application/json'});res.end(value.body);
    });
  });
  server.requestTimeout=2000;server.headersTimeout=2000;
  server.on('clientError',(_error,socket)=>socket.destroy());
  await new Promise((resolve,reject)=>{server.once('error',()=>reject(Error('MOCK_LISTENER_FAILED')));server.listen({host:'127.0.0.1',port:0,exclusive:true},resolve);});
  const port=server.address().port;
  const exchange=(step,request)=>new Promise((resolve,reject)=>{
    const start=performance.now();let tcp=null,tls=null,first=null,settled=false,bytes=0;
    const timing=()=>({source:'local-tls-measurement',dnsPerformed:false,dnsReason:'NUMERIC_LOOPBACK_NO_DNS',
      tcpConnectMs:tcp===null?null:tcp-start,tlsHandshakeMs:tls===null||tcp===null?null:tls-tcp,
      firstByteMs:first===null?null:first-start,totalMs:performance.now()-start,tlsVerified:tls!==null});
    const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(deadline);error?reject(Error(error)):resolve({...value,timing:timing()});};
    const req=https.request({hostname:'127.0.0.1',port,method:request.method,
      path:new URL(request.url).pathname+new URL(request.url).search,headers:request.headers,
      agent:false,ca:certificate,rejectUnauthorized:true,minVersion:'TLSv1.2'},res=>{
      first=performance.now();const chunks=[];
      res.on('data',chunk=>{bytes+=chunk.length;if(bytes>32768){finish('MOCK_RESPONSE_SIZE_LIMIT');res.destroy();req.destroy();}else chunks.push(chunk);});
      res.on('end',()=>finish(null,{httpStatus:res.statusCode,body:Buffer.concat(chunks).toString('utf8')}));
      res.on('error',()=>finish('MOCK_RESPONSE_ABORTED'));
      res.on('aborted',()=>finish('MOCK_RESPONSE_ABORTED'));
    });
    const deadline=setTimeout(()=>{finish('MOCK_HTTP_TIMEOUT');req.destroy();},1000);
    req.on('socket',socket=>{
      socket.once('connect',()=>{tcp=performance.now();if(socket.remoteAddress!=='127.0.0.1')req.destroy();});
      socket.once('secureConnect',()=>{if(socket.authorized)tls=performance.now();else req.destroy();});
    });
    req.on('upgrade',(res,socket)=>{first=performance.now();finish(null,{httpStatus:res.statusCode,body:''});socket.destroy();});
    req.on('error',()=>finish('MOCK_TRANSPORT_FAILURE'));
    if(request.body!==null)req.write(request.body);req.end();
  });
  handle=register('loopback-tls',scenario,context,exchange,{port,close:()=>new Promise(resolve=>{
    server.close(resolve);server.closeAllConnections();
  })});
  return handle;
}
