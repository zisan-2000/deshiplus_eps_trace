// Offline data validation only. Limits below are toolkit safety policy.
export const MAX_JSON_BYTES = 32768;
export const MAX_JSON_DEPTH = 32;
export const MAX_TOKEN_CHARS = 8192;
export const MAX_REDIRECT_CHARS = 4096;
export const MAX_REFERENCE_CHARS = 160;

export const isRecord = value => value !== null && typeof value === 'object' &&
  !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
export const own = (value, key) => Object.hasOwn(value, key);
export const nonBlank = value => typeof value === 'string' && value.trim().length > 0;
export const validMerchantTransactionId = value => typeof value === 'string' && /^[0-9]{10,30}$/.test(value);
export const validCustomerOrderId = value => nonBlank(value) && value.length <= MAX_REFERENCE_CHARS && !/[\x00-\x1f\x7f]/.test(value);
export const validToken = value => typeof value === 'string' && value.length > 0 &&
  value.length <= MAX_TOKEN_CHARS && /^[A-Za-z0-9._~+/-]+=*$/.test(value);
export function normalizeAmount(value) {
  if (!['string', 'number'].includes(typeof value) || !/^[0-9]{1,8}(\.[0-9]{1,2})?$/.test(String(value))) return null;
  const [whole, fraction = ''] = String(value).split('.');
  return BigInt(whole).toString() + '.' + fraction.padEnd(2, '0');
}
export function expectedTransaction(context) {
  if (!isRecord(context) || !own(context, 'merchantTransactionId') || !validMerchantTransactionId(context.merchantTransactionId) ||
      !own(context, 'amount')) return null;
  const amount = normalizeAmount(context.amount);
  return amount && amount !== '0.00' ? { merchantTransactionId: context.merchantTransactionId, amount } : null;
}
export function hasCasingAlias(value, names) {
  const canonical = new Map(names.map(name => [name.toLowerCase(), name]));
  return Object.keys(value).some(key => canonical.has(key.toLowerCase()) && canonical.get(key.toLowerCase()) !== key);
}
export function publicHttps(value) {
  if (typeof value !== 'string' || value.trim() !== value || /[\x00-\x20\x7f]/.test(value)) return false;
  try {
    const u = new URL(value), host = u.hostname.toLowerCase().replace(/\.$/, '');
    return u.protocol === 'https:' && !u.username && !u.password && !u.hash &&
      /[a-z]/i.test(host) && host.includes('.') && !host.includes(':') &&
      !/(^|\.)(localhost|local|test|invalid)$/.test(host);
  } catch { return false; }
}

// JSON.parse validates grammar first; this scanner then rejects duplicate keys
// (including escaped aliases) and excessive nesting before any contract decision.
function structureIssue(text) {
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      const start = i;
      while (++i < text.length) {
        if (text[i] === '\\') { i++; continue; }
        if (text[i] === '"') break;
      }
      const top = stack.at(-1);
      if (top?.object && top.keyExpected) {
        const key = JSON.parse(text.slice(start, i + 1));
        if (top.keys.has(key)) return 'DUPLICATE_JSON_KEY';
        top.keys.add(key); top.keyExpected = false;
      }
    } else if (ch === '{' || ch === '[') {
      stack.push({ object: ch === '{', keyExpected: ch === '{', keys: new Set() });
      if (stack.length > MAX_JSON_DEPTH) return 'JSON_DEPTH_LIMIT_EXCEEDED';
    } else if (ch === '}' || ch === ']') stack.pop();
    else if (ch === ',' && stack.at(-1)?.object) stack.at(-1).keyExpected = true;
  }
  return null;
}

// Internal parsed values can contain secrets. Public validators return codes only.
export function parseJsonObject(body) {
  if (typeof body !== 'string' && !Buffer.isBuffer(body)) return { code: 'JSON_DOCUMENT_REQUIRED' };
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  if (bytes.length > MAX_JSON_BYTES) return { code: 'JSON_SIZE_LIMIT_EXCEEDED' };
  let text, value;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { return { code: 'INVALID_UTF8' }; }
  try { value = JSON.parse(text); }
  catch { return { code: 'INVALID_JSON' }; }
  const code = structureIssue(text);
  if (code) return { code };
  if (!isRecord(value)) return { code: 'JSON_OBJECT_REQUIRED' };
  return { value, code: null };
}
