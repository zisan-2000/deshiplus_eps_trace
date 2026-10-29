import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import fs from 'node:fs';
import { ENDPOINTS } from '../src/eps-contract.mjs';
import { createMockContext } from '../src/mock-data.mjs';
import { buildEpsRequest } from '../src/request-builder.mjs';
import { createLocalLiveTransportTestHarness } from '../src/live-http-transport.mjs';
import { validateEpsResponse } from '../src/response-contract.mjs';

const key=fs.readFileSync(new URL('./fixtures/mock-loopback-key.pem',import.meta.url));
const cert=fs.readFileSync(new URL('./fixtures/mock-loopback-cert.pem',import.meta.url));
async function listener() {
  const context=createMockContext();
  const server=https.createServer({key,cert,minVersion:'TLSv1.2'},(req,res)=>{
    const step=Object.keys(ENDPOINTS).find(name=>new URL(ENDPOINTS[name]).pathname===req.url?.split('?')[0]);
    const body=step==='AUTH'?{token:'SYNTHETIC_OPAQUE_AUTH_TOKEN',errorCode:null,errorMessage:null}:
      step==='INITIALIZE'?{RedirectURL:'https://sandbox.eps.com.bd/SYNTHETIC_HOSTED_PAYMENT_NOT_OPENED',TransactionId:'SYNTHETIC_REFERENCE',ErrorCode:null,ErrorMessage:null}:
      {MerchantTransactionId:context.merchantTransactionId,TotalAmount:context.amount,Status:'Success',ErrorCode:null,ErrorMessage:null};
    res.writeHead(step?200:404,{'Content-Type':'application/json'});res.end(JSON.stringify(body));
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen({host:'127.0.0.1',port:0,exclusive:true},resolve);});
  return {server,context,port:server.address().port};
}

test('prepared HTTPS transport runs exact AUTH -> INITIALIZE -> STATUS against forced loopback only',async()=>{
  const {server,context,port}=await listener();
  try {
    const transport=createLocalLiveTransportTestHarness({port,ca:cert});
    const auth=await transport.exchange('AUTH',buildEpsRequest('AUTH',context),context);
    assert.equal(validateEpsResponse('AUTH',auth,context).accepted,true);
    context.token=JSON.parse(auth.body).token;
    const init=await transport.exchange('INITIALIZE',buildEpsRequest('INITIALIZE',context),context);
    assert.equal(validateEpsResponse('INITIALIZE',init,context).accepted,true);
    const status=await transport.exchange('STATUS',buildEpsRequest('STATUS',context),context);
    const verified=validateEpsResponse('STATUS',status,context);
    assert.equal(verified.paymentVerified,true);
    for(const raw of [auth,init,status]) {
      assert.equal(raw.timing.source,'local-live-transport-test'); assert.equal(raw.timing.dnsPerformed,true);
      assert.equal(raw.timing.tlsVerified,true); assert.ok(raw.timing.tcpConnectMs>=0);assert.ok(raw.timing.tlsHandshakeMs>=0);
      assert.ok(raw.timing.firstByteMs>=0);assert.ok(raw.timing.totalMs>=raw.timing.firstByteMs);
    }
    await assert.rejects(()=>transport.exchange('STATUS',buildEpsRequest('STATUS',context),context),/LIVE_AUTOMATIC_RETRY_FORBIDDEN/);
  } finally {await new Promise(resolve=>server.close(resolve));server.closeAllConnections();}
});
