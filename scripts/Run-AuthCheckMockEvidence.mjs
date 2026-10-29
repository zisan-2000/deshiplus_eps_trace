import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createLocalAuthOnlyExchange } from '../src/auth-only-http.mjs';
import { runAuthCheck, AUTH_ONLY_CONFIRMATION } from '../src/auth-check-runner.mjs';
import { runCaptureProbe, localToolEnvironment } from '../src/capture-readiness.mjs';

const key=fs.readFileSync(new URL('../tests/fixtures/mock-loopback-key.pem',import.meta.url));
const cert=fs.readFileSync(new URL('../tests/fixtures/mock-loopback-cert.pem',import.meta.url));
const server=https.createServer({key,cert,minVersion:'TLSv1.2'},(req,res)=>{
  const chunks=[];req.on('data',chunk=>chunks.push(chunk));req.on('end',()=>{
    if(req.method!=='POST'||req.url!=='/v1/Auth/GetToken'){res.writeHead(404);res.end();return;}
    try{const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(Object.keys(body).sort().join()!=='password,userName')throw Error();}
    catch{res.writeHead(400);res.end();return;}
    res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({token:'SYNTHETIC_AUTH_TOKEN_NOT_PERSISTED',errorCode:null,errorMessage:null}));
  });
});
try{
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen({host:'127.0.0.1',port:0,exclusive:true},resolve);});
  const port=server.address().port,exchange=createLocalAuthOnlyExchange({port,ca:cert});
  const environment={EPS_AUTH_ONLY_CONFIRMATION:AUTH_ONLY_CONFIRMATION,EPS_USERNAME:'SYNTHETIC_USER',EPS_PASSWORD:'SYNTHETIC_PASSWORD',EPS_HASH_KEY:'SYNTHETIC_HASH_KEY'};
  const capture=async(cfg,directory,flow)=>{
    const valueHolder={value:null};
    const result=await runCaptureProbe({kind:'loopback',port,tsharkPath:cfg.capture.tsharkPath,outputDirectory:directory},async()=>{valueHolder.value=await flow();});
    const pcap=path.join(directory,'session.pcapng');
    const read=spawnSync(cfg.capture.tsharkPath,['-n','-r',pcap,'-T','fields','-e','frame.number'],{encoding:'utf8',windowsHide:true,shell:false,env:localToolEnvironment(),timeout:10000});
    if(read.error||read.status!==0)throw Error('AUTH_CAPTURE_READ_FAILED');
    return{value:valueHolder.value,capture:{ready:result.ready,bytes:result.pcapBytes,packetCount:read.stdout.split(/\r?\n/).filter(Boolean).length}};
  };
  const result=await runAuthCheck({environment,exchange,capture,outputParent:'evidence/auth-check-mock',evidenceScope:'LOCAL_LOOPBACK_AUTH_ONLY_NOT_EPS'});
  console.log(JSON.stringify({outcome:result.report.outcome,scope:'LOCAL_LOOPBACK_ONLY',directory:result.directory,combinedReport:'combined-report.json',pcap:'session.pcapng',liveRequestSent:false},null,2));
}catch{console.error(JSON.stringify({outcome:'FAIL',code:'AUTH_ONLY_LOCAL_EVIDENCE_FAILED'}));process.exitCode=1;}
finally{await new Promise(resolve=>server.close(resolve));server.closeAllConnections();}
