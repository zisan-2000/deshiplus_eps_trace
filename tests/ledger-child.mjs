import { AttemptLedger } from '../src/attempt-ledger.mjs';
try {
  new AttemptLedger(process.argv[2]).reserve({merchantTransactionId:process.argv[3],customerOrderId:process.argv[4],amount:'10.00'});
  process.stdout.write('RESERVED');
} catch(error) {
  process.stdout.write(['LEDGER_DUPLICATE_INITIALIZE_FORBIDDEN','LEDGER_LOCKED_RECONCILIATION_REQUIRED'].includes(error.message)?error.message:'FAILED');
}
