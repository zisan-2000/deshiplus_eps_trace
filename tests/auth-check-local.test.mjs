import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import fs from 'node:fs';
import { createLocalAuthOnlyExchange } from '../src/auth-only-http.mjs';
import { validateEpsResponse } from '../src/response-contract.mjs';

const key=fs.readFileSync(new URL('./fixtures/mock-loopback-key.pem',import.meta.url));
const cert=fs.readFileSync(new URL('./fixtures/mock-loopback-cert.pem',import.meta.url));
test('AUTH-only transport sends one exact POST through forced loopback and measures DNS/TCP/TLS/HTTP',async()=>{
  let requests=0,method=null,url=null,headers=null,body=null;
  const server=https.createServer({key,cert,minVersion:'TLSv1.2'},(req,res)=>{requests++;method=req.method;url=req.url;headers=req.headers;const chunks=[];
    req.on('data',chunk=>chunks.push(chunk));req.on('end',()=>{body=Buffer.concat(chunks).toString('utf8');res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({token:'SYNTHETIC_TOKEN',errorCode:null,errorMessage:null}));});});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen({host:'127.0.0.1',port:0,exclusive:true},resolve);});
  try{
    const exchange=createLocalAuthOnlyExchange({port:server.address().port,ca:cert});
    const raw=await exchange({username:'SYNTHETIC_USER',password:'SYNTHETIC_PASSWORD',hashKey:'SYNTHETIC_HASH_KEY'});
    assert.equal(validateEpsResponse('AUTH',raw,{}).accepted,true);assert.equal(requests,1);assert.equal(method,'POST');assert.equal(url,'/v1/Auth/GetToken');
    assert.deepEqual(Object.keys(JSON.parse(body)).sort(),['password','userName']);assert.equal(typeof headers['x-hash'],'string');
    for(const key of ['dnsMs','tcpConnectMs','tlsHandshakeMs','firstByteMs','totalMs'])assert.ok(raw.timing[key]>=0,key);
    assert.equal(raw.timing.tlsVerified,true);
    await assert.rejects(()=>exchange({username:'SYNTHETIC_USER',password:'SYNTHETIC_PASSWORD',hashKey:'SYNTHETIC_HASH_KEY'}),/AUTH_ONLY_RETRY_FORBIDDEN/);
  }finally{await new Promise(resolve=>server.close(resolve));server.closeAllConnections();}
});
