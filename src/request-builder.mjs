import { ENDPOINTS } from './eps-contract.mjs';
import { epsXHash } from './signing.mjs';
import { validateEpsRequest } from './request-contract.mjs';

const customerFields = Object.freeze({
  customerName: 'customerName', customerEmail: 'customerEmail', customerAddress: 'customerAddress',
  customerCity: 'customerCity', customerState: 'customerState', customerPostcode: 'customerPostcode',
  customerCountry: 'customerCountry', customerPhone: 'customerPhone', productName: 'productName'
});
export function buildEpsRequest(step, context) {
  if (!Object.hasOwn(ENDPOINTS, step)) throw Error('REQUEST_STEP_INVALID');
  const auth=step==='AUTH';
  let body=null;
  if(auth) body={userName:context.username,password:context.password};
  else if(step==='INITIALIZE') body={merchantId:context.merchantId,storeId:context.storeId,
    CustomerOrderId:context.customerOrderId,merchantTransactionId:context.merchantTransactionId,
    transactionTypeId:1,totalAmount:Number(context.amount),successUrl:context.successUrl,
    failUrl:context.failUrl,cancelUrl:context.cancelUrl,
    ...Object.fromEntries(Object.entries(customerFields).map(([wire,key])=>[wire,context[key]]))};
  const request={method:step==='STATUS'?'GET':'POST',url:ENDPOINTS[step]+
    (step==='STATUS'?'?merchantTransactionId='+context.merchantTransactionId:''),
    headers:{'Content-Type':'application/json','x-hash':epsXHash(auth?context.username:context.merchantTransactionId,context.hashKey),
      ...(auth?{}:{Authorization:'Bearer '+context.token})},body:body===null?null:JSON.stringify(body)};
  const checked=validateEpsRequest(step,request,context);
  if(!checked.accepted)throw Error('BUILT_REQUEST_CONTRACT_REJECTED');
  return request;
}
