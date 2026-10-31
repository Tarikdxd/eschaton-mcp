import { existsSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { commandVersion, runCommand } from './exec.ts';
import { assertTarget, normalizeHost, type Scope } from './scope.ts';

export interface ToolContext {
  scope: Scope;
  dryRun: boolean;
}

const MAX_OUTPUT = 20_000;
const FIVE_MINUTES = 5 * 60 * 1000;
const TEN_MINUTES = 10 * 60 * 1000;
const FIFTEEN_MINUTES = 15 * 60 * 1000;
const THIRTY_MINUTES = 30 * 60 * 1000;

function text(args: Record<string, unknown>, key: string): string {
  const value = args[key];
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${key} zorunlu bir metin`);
  return value.trim();
}

function optionalText(args: Record<string, unknown>, key: string): string | undefined {
  const value = args[key];
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') throw new Error(`${key} metin olmalı`);
  return value.trim();
}

function integer(
  args: Record<string, unknown>,
  key: string,
  min: number,
  max: number,
  fallback: number,
): number {
  const value = args[key];
  if (value === undefined || value === null) return fallback;
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${key} ${min}-${max} arasında tam sayı olmalı`);
  }
  return parsed;
}

export function validatePorts(ports: string): string {
  if (!/^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$/.test(ports)) {
    throw new Error('ports biçimi: 80,443,8000-8100');
  }
  for (const part of ports.split(',')) {
    for (const bound of part.split('-')) {
      const value = Number(bound);
      if (value < 1 || value > 65535) throw new Error('port 1-65535 aralığında olmalı');
    }
  }
  return ports;
}

export function buildNmapArgs(
  args: Record<string, unknown>,
  scope: Scope,
): { cmd: string; argv: string[]; timeoutMs: number } {
  const host = assertTarget(text(args, 'target'), scope);
  const ports = optionalText(args, 'ports');
  const topPorts = args.topPorts === undefined ? undefined : integer(args, 'topPorts', 1, 65535, 100);
  const service = args.serviceDetection === true;

  const argv = ['-Pn', '-T3', '--max-retries', '2'];
  if (topPorts !== undefined) argv.push('--top-ports', String(topPorts));
  if (ports) argv.push('-p', validatePorts(ports));
  if (service) argv.push('-sV');
  argv.push(host);
  return { cmd: 'nmap', argv, timeoutMs: FIFTEEN_MINUTES };
}

export function buildHttpxArgs(
  args: Record<string, unknown>,
  scope: Scope,
): { cmd: string; argv: string[]; timeoutMs: number } {
  const raw = args.targets;
  const list = Array.isArray(raw) ? raw : [raw];
  if (list.length === 0 || list.length > 20) throw new Error('1-20 hedef girin');
  const targets = list.map((item) => {
    if (typeof item !== 'string') throw new Error('targets metin listesi olmalı');
    assertTarget(item, scope);
    return item.trim();
  });
  const argv = ['-silent', '-status-code', '-title', '-tech-detect', '-no-color', '-timeout', '10'];
  for (const target of targets) argv.push('-u', target);
  return { cmd: 'httpx', argv, timeoutMs: FIVE_MINUTES };
}

export function buildFfufArgs(
  args: Record<string, unknown>,
  scope: Scope,
): { cmd: string; argv: string[]; timeoutMs: number } {
  const url = text(args, 'url');
  if (!url.includes('FUZZ')) throw new Error('url bir FUZZ yer tutucusu içermeli');
  const parsed = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
  if (parsed.hostname.includes('FUZZ')) throw new Error('host üzerinde FUZZ bu sürümde desteklenmiyor');
  assertTarget(url, scope);

  const wordlist = text(args, 'wordlist');
  if (!isAbsolute(wordlist)) throw new Error('wordlist mutlak bir yol olmalı');
  if (!existsSync(wordlist) || !statSync(wordlist).isFile()) {
    throw new Error('wordlist bulunamadı veya dosya değil');
  }
  if (statSync(wordlist).size > 50 * 1024 * 1024) throw new Error('wordlist 50 MB sınırını aşıyor');

  const method = (optionalText(args, 'method') ?? 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'POST') throw new Error('method GET veya POST olmalı');
  const matchCodes = optionalText(args, 'matchCodes') ?? '200,204,301,302,307,401,403';
  if (!/^\d{3}(,\d{3})*$/.test(matchCodes)) throw new Error('matchCodes: 200,204,301 gibi');
  const rate = integer(args, 'rate', 1, 200, 50);

  const argv = ['-u', url, '-w', wordlist, '-mc', matchCodes, '-rate', String(rate), '-s', '-noninteractive'];
  if (method === 'POST') argv.push('-X', 'POST');
  return { cmd: 'ffuf', argv, timeoutMs: TEN_MINUTES };
}

export function buildSqlmapArgs(
  args: Record<string, unknown>,
  scope: Scope,
): { cmd: string; argv: string[]; timeoutMs: number } {
  const url = text(args, 'url');
  assertTarget(url, scope);
  const level = integer(args, 'level', 1, 3, 1);
  const risk = integer(args, 'risk', 1, 2, 1);
  const data = optionalText(args, 'data');
  if (data && data.length > 8192) throw new Error('data 8 KB sınırını aşıyor');
  const argv = ['-u', url, '--batch', '--level', String(level), '--risk', String(risk)];
  if (data) argv.push('--data', data);
  return { cmd: 'sqlmap', argv, timeoutMs: THIRTY_MINUTES };
}

export function buildNucleiArgs(
  args: Record<string, unknown>,
  scope: Scope,
): { cmd: string; argv: string[]; timeoutMs: number } {
  const target = text(args, 'target');
  assertTarget(target, scope);

  const severity = optionalText(args, 'severity');
  if (severity && !/^(info|low|medium|high|critical)(,(info|low|medium|high|critical))*$/.test(severity)) {
    throw new Error('severity: info,low,medium,high,critical');
  }

  const tags = optionalText(args, 'tags');
  if (tags && !/^[a-zA-Z0-9_,-]+$/.test(tags)) {
    throw new Error('tags yalnızca harf, rakam, _ ve - içerebilir');
  }

  const templates = optionalText(args, 'templates');
  if (templates) {
    if (!isAbsolute(templates)) throw new Error('templates mutlak bir yol olmalı');
    if (!existsSync(templates)) throw new Error('templates bulunamadı');
  }

  const rate = integer(args, 'rate', 1, 150, 50);
  const argv = ['-u', target, '-silent', '-jsonl', '-no-color', '-rate', String(rate)];
  if (severity) argv.push('-severity', severity);
  if (tags) argv.push('-tags', tags);
  if (templates) argv.push('-t', templates);
  return { cmd: 'nuclei', argv, timeoutMs: FIFTEEN_MINUTES };
}

function truncate(value: string): string {
  return value.length <= MAX_OUTPUT ? value : `${value.slice(0, MAX_OUTPUT)}\n… (çıktı kısaltıldı)`;
}

export async function toolchainStatus(): Promise<string> {
  const tools = [
    { bin: 'nmap', purpose: 'port/servis taraması' },
    { bin: 'httpx', purpose: 'HTTP parmak izi' },
    { bin: 'ffuf', purpose: 'içerik keşfi' },
    { bin: 'sqlmap', purpose: 'SQL enjeksiyonu doğrulama' },
    { bin: 'nuclei', purpose: 'şablon tabanlı tarama' },
  ];
  const lines: string[] = [];
  for (const tool of tools) {
    const version = await commandVersion(tool.bin);
    lines.push(`${tool.bin.padEnd(8)} ${version}  (${tool.purpose})`);
  }
  return lines.join('\n');
}

export async function runTool(
  name: string,
  rawArgs: unknown,
  ctx: ToolContext,
): Promise<string> {
  const args = rawArgs && typeof rawArgs === 'object' ? (rawArgs as Record<string, unknown>) : {};

  if (name === 'toolchain_status') return toolchainStatus();

  let plan: { cmd: string; argv: string[]; timeoutMs: number };
  if (name === 'nmap_scan') plan = buildNmapArgs(args, ctx.scope);
  else if (name === 'httpx_probe') plan = buildHttpxArgs(args, ctx.scope);
  else if (name === 'ffuf_fuzz') plan = buildFfufArgs(args, ctx.scope);
  else if (name === 'sqlmap_scan') plan = buildSqlmapArgs(args, ctx.scope);
  else if (name === 'nuclei_scan') plan = buildNucleiArgs(args, ctx.scope);
  else throw new Error(`bilinmeyen araç: ${name}`);

  if (ctx.dryRun) {
    return `dry-run: ${plan.cmd} ${plan.argv.map((part) => JSON.stringify(part)).join(' ')}`;
  }

  const result = await runCommand(plan.cmd, plan.argv, plan.timeoutMs);
  const output = [result.stdout.trim(), result.stderr.trim()].filter(Boolean).join('\n');
  const body = output || '(çıktı yok)';
  return result.exitCode === 0 ? truncate(body) : truncate(`çıkış kodu: ${result.exitCode}\n${body}`);
}

export function describeTargets(target: string): string {
  return normalizeHost(target);
}
