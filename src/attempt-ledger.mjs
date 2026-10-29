import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { ownedDirectory, regularFile, writeExclusive, protectPrivateDirectory } from './workspace-storage.mjs';
import { validMerchantTransactionId, validCustomerOrderId, normalizeAmount, parseJsonObject } from './contract-utils.mjs';

export const MOCK_SCOPE = createHash('sha256').update('SYNTHETIC_EPS_SANDBOX_ONLY').digest('hex');
const phases = {
  RESERVE: { from: [null], to: 'RESERVED' }, AUTH_OK: { from: ['RESERVED'], to: 'AUTH_ACCEPTED' },
  AUTH_FAIL: { from: ['RESERVED'], to: 'AUTH_FAILED' },
  CLAIM_INITIALIZE: { from: ['AUTH_ACCEPTED'], to: 'INITIALIZE_IN_FLIGHT' },
  INITIALIZE_OK: { from: ['INITIALIZE_IN_FLIGHT'], to: 'AWAITING_HOSTED_PAYMENT' },
  INITIALIZE_UNCERTAIN: { from: ['INITIALIZE_IN_FLIGHT'], to: 'INITIALIZE_UNCERTAIN' },
  HOSTED_SIMULATED: { from: ['AWAITING_HOSTED_PAYMENT'], to: 'HOSTED_COMPLETION_SIMULATED' },
  OPERATOR_AUTHORIZE_STATUS: { from: ['AWAITING_HOSTED_PAYMENT'], to: 'STATUS_CHECK_AUTHORIZED' },
  CLAIM_REAUTH: { from: ['STATUS_CHECK_AUTHORIZED'], to: 'REAUTH_IN_FLIGHT' },
  REAUTH_OK: { from: ['REAUTH_IN_FLIGHT'], to: 'STATUS_AUTHENTICATED' },
  REAUTH_FAIL: { from: ['REAUTH_IN_FLIGHT'], to: 'STATUS_AUTH_UNCONFIRMED' },
  CLAIM_STATUS: { from: ['HOSTED_COMPLETION_SIMULATED', 'STATUS_AUTHENTICATED'], to: 'STATUS_IN_FLIGHT' },
  STATUS_SUCCESS: { from: ['STATUS_IN_FLIGHT'], to: 'MOCK_SUCCESS' },
  STATUS_UNCONFIRMED: { from: ['STATUS_IN_FLIGHT'], to: 'STATUS_UNCONFIRMED' }
};
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const keys = ['id','merchantTransactionId','customerOrderId','amount','scopeFingerprint','phase'];
function validAttempt(a, scopeFingerprint) {
  return a && Object.keys(a).length === keys.length && keys.every(key => Object.hasOwn(a,key)) &&
    /^[a-f0-9-]{36}$/.test(a.id) && a.scopeFingerprint === scopeFingerprint && validMerchantTransactionId(a.merchantTransactionId) &&
    validCustomerOrderId(a.customerOrderId) && a.customerOrderId.startsWith('DPEPS-' + a.merchantTransactionId + '-') &&
    normalizeAmount(a.amount) === a.amount && a.amount !== '0.00';
}

// Mock scope only. Every reader/writer takes one exclusive lock. Each complete
// fsynced journal event reserves BOTH references or changes ONE phase atomically.
// A torn record, missing journal, stale lock or failed flush blocks all further work.
export class AttemptLedger {
  constructor(directory = '.private/mock-ledger', { scopeFingerprint = MOCK_SCOPE } = {}) {
    if (!/^[a-f0-9]{64}$/.test(scopeFingerprint)) throw Error('LEDGER_SCOPE_INVALID');
    this.scopeFingerprint = scopeFingerprint;
    this.markerValue = scopeFingerprint === MOCK_SCOPE ? 'MOCK_ONLY_LEDGER_V1' : 'EPS_ATTEMPT_LEDGER_V1:' + scopeFingerprint;
    this.directory = ownedDirectory(directory);
    protectPrivateDirectory(this.directory);
    this.lock = path.join(this.directory,'writer.lock');
    this.file = path.join(this.directory,'events.ndjson');
    this.marker = path.join(this.directory,'ledger.origin');
  }
  #locked(operation) {
    ownedDirectory(this.directory);
    let fd;
    try { fd = fs.openSync(this.lock,'wx',0o600); }
    catch { throw Error('LEDGER_LOCKED_RECONCILIATION_REQUIRED'); }
    let poisoned = false;
    try {
      fs.writeFileSync(fd, 'MOCK_ONLY_EXCLUSIVE_LOCK'); fs.fsyncSync(fd);
      let fresh = false;
      if (!fs.existsSync(this.marker)) {
        if (fs.existsSync(this.file)) throw Error('LEDGER_CORRUPT');
        writeExclusive(this.marker,this.markerValue);
        writeExclusive(this.file,''); fresh = true;
      }
      if (!fs.existsSync(this.file) || !regularFile(this.marker) || regularFile(this.file).size > 4 * 1024 * 1024 ||
          fs.readFileSync(this.marker,'utf8') !== this.markerValue) throw Error('LEDGER_CORRUPT');
      const text = fs.readFileSync(this.file,'utf8');
      if ((!text && !fresh) || (text && !text.endsWith('\n'))) throw Error('LEDGER_CORRUPT');
      const entries = new Map(); let sequence = 0, previous = '0'.repeat(64);
      for (const line of text.split('\n').filter(Boolean)) {
        const parsed = parseJsonObject(line); if (parsed.code) throw Error('LEDGER_CORRUPT');
        const { digest, ...event } = parsed.value;
        const rule = phases[event.operation], before = entries.get(event.attempt?.id);
        if (Object.keys(event).sort().join() !== 'attempt,operation,previous,sequence,version' || event.version !== 1 ||
            event.sequence !== ++sequence || event.previous !== previous || digest !== hash(event) ||
            !validAttempt(event.attempt, this.scopeFingerprint) || !rule || !rule.from.includes(before?.phase ?? null) || event.attempt.phase !== rule.to) throw Error('LEDGER_CORRUPT');
        if (before && keys.filter(k=>k!=='phase').some(k=>event.attempt[k]!==before[k])) throw Error('LEDGER_CORRUPT');
        if (!before && [...entries.values()].some(a => a.merchantTransactionId === event.attempt.merchantTransactionId || a.customerOrderId === event.attempt.customerOrderId)) throw Error('LEDGER_CORRUPT');
        entries.set(event.attempt.id,event.attempt); previous = digest;
      }
      return operation(entries, (action, attempt) => {
        const event = { version:1, sequence:sequence+1, previous, operation:action, attempt };
        const line = Buffer.from(JSON.stringify({...event,digest:hash(event)})+'\n');
        let journal;
        try {
          journal=fs.openSync(this.file,'a'); let written=0;
          while(written<line.length) {const count=fs.writeSync(journal,line,written,line.length-written);if(count<1)throw Error('WRITE_FAILED');written+=count;}
          fs.fsyncSync(journal);
        } catch {poisoned=true;throw Error('LEDGER_DURABILITY_FAILURE');}
        finally {if(journal!==undefined)fs.closeSync(journal);}
        return Object.freeze({...attempt});
      });
    } catch(error) {
      if (!/^(LEDGER_|STORAGE_)/.test(error.message)) {poisoned=true;throw Error('LEDGER_STORAGE_FAILURE');}
      if(error.message==='LEDGER_CORRUPT')poisoned=true;
      throw error;
    } finally {
      fs.closeSync(fd);
      if(!poisoned)fs.unlinkSync(this.lock);
    }
  }
  reserve(identity) {
    return this.#locked((entries,append)=>{
      const attempt={id:randomUUID(),merchantTransactionId:identity.merchantTransactionId,customerOrderId:identity.customerOrderId,
        amount:identity.amount,scopeFingerprint:this.scopeFingerprint,phase:'RESERVED'};
      if(!validAttempt(attempt,this.scopeFingerprint))throw Error('LEDGER_IDENTITY_INVALID');
      if([...entries.values()].some(a=>a.merchantTransactionId===attempt.merchantTransactionId||a.customerOrderId===attempt.customerOrderId))throw Error('LEDGER_DUPLICATE_INITIALIZE_FORBIDDEN');
      return append('RESERVE',attempt);
    });
  }
  inspect(id) {
    return this.#locked(entries=>{const value=entries.get(id);if(!value)throw Error('LEDGER_ATTEMPT_NOT_FOUND');return Object.freeze({...value});});
  }
  transition(id,action) {
    return this.#locked((entries,append)=>{
      const before=entries.get(id),rule=phases[action];
      if(!before||!rule||action==='RESERVE'||!rule.from.includes(before.phase))throw Error('LEDGER_PHASE_REJECTED');
      return append(action,{...before,phase:rule.to});
    });
  }
}
