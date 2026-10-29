import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
export const PROJECT_ROOT = fileURLToPath(new URL('../', import.meta.url));
export function ownedDirectory(target) {
  const absolute = path.resolve(PROJECT_ROOT, target);
  const relative = path.relative(PROJECT_ROOT, absolute);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative) ||
      !['.private', 'evidence', 'tmp'].includes(relative.split(path.sep)[0])) throw Error('STORAGE_PATH_FORBIDDEN');
  let current = PROJECT_ROOT;
  for (const part of relative.split(path.sep)) {
    current = path.join(current, part);
    try { fs.mkdirSync(current, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw Error('STORAGE_CREATE_FAILED'); }
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error('STORAGE_LINK_FORBIDDEN');
  }
  return absolute;
}
export function regularFile(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw Error('STORAGE_LINK_FORBIDDEN');
  return stat;
}
export function writeExclusive(file, value) {
  const fd = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(fd, value); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
const protectedDirectories = new Set();
export function protectPrivateDirectory(directory) {
  ownedDirectory(directory);
  if(protectedDirectories.has(directory))return;
  if(process.platform==='win32') {
    const env={};for(const name of ['SystemRoot','WINDIR','Path','PATHEXT','COMSPEC','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','PSModulePath','ProgramFiles','ProgramFiles(x86)','ProgramW6432'])if(process.env[name])env[name]=process.env[name];
    const result=spawnSync(path.join(env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),
      ['-NoProfile','-NonInteractive','-File',path.join(PROJECT_ROOT,'scripts/Protect-MockLedger.ps1'),'-Directory',directory],
      {env,windowsHide:true,shell:false,stdio:'ignore',timeout:30000});
    if(result.status!==0||result.error)throw Error('LEDGER_PRIVATE_ACL_FAILED');
  }else fs.chmodSync(directory,0o700);
  protectedDirectories.add(directory);
}
