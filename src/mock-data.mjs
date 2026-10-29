import { randomBytes, randomInt } from 'node:crypto';
import { SYNTHETIC_CUSTOMER_ENV } from './environment-preflight.mjs';
import { buildEpsRequest } from './request-builder.mjs';
// Only generated/synthetic data. This module never reads process.env or .env.
export function createMockContext(attempt) {
  const merchantTransactionId=attempt?.merchantTransactionId ?? String(Date.now())+String(randomInt(0,10_000_000_000)).padStart(10,'0');
  const customerOrderId=attempt?.customerOrderId ?? 'DPEPS-'+merchantTransactionId+'-'+randomBytes(8).toString('hex');
  return {merchantTransactionId,customerOrderId,amount:attempt?.amount??'10.00',
    username:'SYNTHETIC_EPS_USERNAME',password:'SYNTHETIC_EPS_PASSWORD',hashKey:'SYNTHETIC_UTF8_HASH_KEY',
    merchantId:'SYNTHETIC_MERCHANT',storeId:'SYNTHETIC_STORE',token:null,
    callbackOrigin:'https://callbacks.example.com',ecommerceOrigins:['https://shop.example.com'],
    successUrl:'https://callbacks.example.com/eps-trace/success',failUrl:'https://callbacks.example.com/eps-trace/fail',
    cancelUrl:'https://callbacks.example.com/eps-trace/cancel',
    customerName:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_CUSTOMER_NAME,customerEmail:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_CUSTOMER_EMAIL,
    customerAddress:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_CUSTOMER_ADDRESS,customerCity:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_CUSTOMER_CITY,
    customerState:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_CUSTOMER_STATE,customerPostcode:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_CUSTOMER_POSTCODE,
    customerCountry:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_CUSTOMER_COUNTRY,customerPhone:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_CUSTOMER_PHONE,
    productName:SYNTHETIC_CUSTOMER_ENV.EPS_TRACE_PRODUCT_NAME};
}
export const mockRequest = buildEpsRequest;
