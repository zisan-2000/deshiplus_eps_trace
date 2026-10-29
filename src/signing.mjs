import { createHmac } from 'node:crypto';

// Pure offline primitive. Neither argument is fetched from disk or environment here.
// EPS hash keys are UTF-8 text, not Base64-decoded keys. Never log the return value.
export function epsXHash(input, hashKey) {
  if (typeof input !== 'string' || !input || typeof hashKey !== 'string' || !hashKey) {
    throw new Error('SIGNING_INPUT_INVALID');
  }
  return createHmac('sha512', Buffer.from(hashKey, 'utf8')).update(input, 'utf8').digest('base64');
}
