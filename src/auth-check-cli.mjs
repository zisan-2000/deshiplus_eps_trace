#!/usr/bin/env node
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { runAuthCheck } from './auth-check-runner.mjs';

export async function main(args=process.argv.slice(2),environment=process.env){
  try{
    if(args.length)throw Error('AUTH_ONLY_ARGUMENTS_FORBIDDEN');
    const result=await runAuthCheck({environment});
    console.log(JSON.stringify({outcome:result.report.outcome,code:result.report.code,evidenceDirectory:result.directory,
      combinedReport:'combined-report.json',pcap:result.report.capture?'session.pcapng':null},null,2));
    return result.report.outcome==='PASS'?0:1;
  }catch{console.error(JSON.stringify({outcome:'FAIL',code:'AUTH_ONLY_PRECHECK_FAILED'}));return 1;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)process.exitCode=await main();
