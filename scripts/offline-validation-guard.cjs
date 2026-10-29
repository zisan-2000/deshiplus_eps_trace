// Preloaded only for the private helper's fixed Node validation child.
// An unexpected network/child-process operation aborts before it can execute.
const deny = () => { throw new Error('PRIVATE_PREFLIGHT_NETWORK_OR_PROCESS_FORBIDDEN'); };
const net = require('node:net');
net.Socket.prototype.connect = deny;
net.Server.prototype.listen = deny;
const dgram = require('node:dgram');
dgram.Socket.prototype.send = deny; dgram.Socket.prototype.connect = deny; dgram.Socket.prototype.bind = deny;
for (const name of ['node:http', 'node:https']) { const module = require(name); module.request = deny; module.get = deny; }
const dns = require('node:dns');
for (const target of [dns, dns.promises]) for (const key of Object.keys(target)) {
  if (/^(lookup|resolve|reverse)/.test(key) && typeof target[key] === 'function') target[key] = deny;
}
const child = require('node:child_process');
for (const key of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) child[key] = deny;
globalThis.fetch = deny;
require('node:module').syncBuiltinESMExports();
