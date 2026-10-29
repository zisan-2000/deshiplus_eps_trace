// Test-only tripwire. No real EPS request or socket is permitted in this suite.
const deny = () => { throw new Error('OFFLINE_TEST_NETWORK_FORBIDDEN'); };
require('node:net').Socket.prototype.connect = deny;
const dgram = require('node:dgram');
dgram.Socket.prototype.connect = deny;
dgram.Socket.prototype.send = deny;
for (const moduleName of ['node:http', 'node:https']) {
  const module = require(moduleName);
  module.request = deny;
  module.get = deny;
}
const dns = require('node:dns');
for (const key of Object.keys(dns)) {
  if (/^(lookup|resolve|reverse)/.test(key) && typeof dns[key] === 'function') dns[key] = deny;
}
for (const key of Object.keys(dns.promises)) {
  if (/^(lookup|resolve|reverse)/.test(key) && typeof dns.promises[key] === 'function') dns.promises[key] = deny;
}
globalThis.fetch = deny;
