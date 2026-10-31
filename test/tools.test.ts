import { describe, expect, it, afterAll } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildFfufArgs,
  buildNmapArgs,
  buildNucleiArgs,
  buildSqlmapArgs,
  runTool,
  validatePorts,
} from '../src/tools.ts';
import type { Scope } from '../src/scope.ts';

const scope: Scope = { allowed: ['example.com'], allowPrivate: false };
const dir = mkdtempSync(join(tmpdir(), 'eschaton-mcp-'));
const wordlist = join(dir, 'words.txt');
writeFileSync(wordlist, 'admin\nlogin\n');

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('validatePorts', () => {
  it('geçerli biçimleri kabul eder', () => {
    expect(validatePorts('80,443,8000-8100')).toBe('80,443,8000-8100');
  });
  it('geçersiz biçimleri reddeder', () => {
    expect(() => validatePorts('80; rm -rf /')).toThrow();
    expect(() => validatePorts('70000')).toThrow();
  });
});

describe('buildNmapArgs', () => {
  it('kapsam içi hedef için güvenli argv üretir', () => {
    const plan = buildNmapArgs({ target: 'https://api.example.com', topPorts: 100, serviceDetection: true }, scope);
    expect(plan.cmd).toBe('nmap');
    expect(plan.argv).toContain('api.example.com');
    expect(plan.argv).toContain('--top-ports');
    expect(plan.argv).toContain('-sV');
  });

  it('kapsam dışı hedefi reddeder', () => {
    expect(() => buildNmapArgs({ target: 'https://evil.test' }, scope)).toThrow(/kapsam dışı/);
  });

  it('port enjeksiyonunu reddeder', () => {
    expect(() => buildNmapArgs({ target: 'example.com', ports: '80; touch /tmp/pwned' }, scope)).toThrow();
  });
});

describe('buildFfufArgs', () => {
  it('FUZZ içeren URL ve mevcut wordlist ile argv üretir', () => {
    const plan = buildFfufArgs({ url: 'https://example.com/FUZZ', wordlist, rate: 25 }, scope);
    expect(plan.argv).toContain('-u');
    expect(plan.argv).toContain('https://example.com/FUZZ');
    expect(plan.argv).toContain(wordlist);
    expect(plan.argv).toContain('25');
  });

  it('FUZZ yoksa reddeder', () => {
    expect(() => buildFfufArgs({ url: 'https://example.com/', wordlist }, scope)).toThrow(/FUZZ/);
  });

  it('göreli wordlist yolunu reddeder', () => {
    expect(() => buildFfufArgs({ url: 'https://example.com/FUZZ', wordlist: 'words.txt' }, scope)).toThrow(
      /mutlak/,
    );
  });
});

describe('buildSqlmapArgs', () => {
  it('seviye/risk sınırlarını uygular', () => {
    const plan = buildSqlmapArgs({ url: 'https://example.com/item?id=1', level: 2, risk: 2 }, scope);
    expect(plan.argv).toContain('--batch');
    expect(plan.argv).toContain('2');
    expect(() => buildSqlmapArgs({ url: 'https://example.com', level: 5 }, scope)).toThrow();
  });
});

describe('buildNucleiArgs', () => {
  it('kapsam içi hedef için severity/tags/rate üretir', () => {
    const plan = buildNucleiArgs(
      { target: 'https://example.com', severity: 'high,critical', tags: 'cve,rce', rate: 25 },
      scope,
    );
    expect(plan.cmd).toBe('nuclei');
    expect(plan.argv).toContain('-severity');
    expect(plan.argv).toContain('high,critical');
    expect(plan.argv).toContain('-tags');
    expect(plan.argv).toContain('cve,rce');
    expect(plan.argv).toContain('25');
  });

  it('kapsam dışı hedefi reddeder', () => {
    expect(() => buildNucleiArgs({ target: 'https://evil.test' }, scope)).toThrow(/kapsam dışı/);
  });

  it('geçersiz severity, rate ve göreli şablon yolunu reddeder', () => {
    expect(() => buildNucleiArgs({ target: 'example.com', severity: 'urgent' }, scope)).toThrow(
      /severity/,
    );
    expect(() => buildNucleiArgs({ target: 'example.com', rate: 0 }, scope)).toThrow(/rate/);
    expect(() => buildNucleiArgs({ target: 'example.com', templates: 'templates' }, scope)).toThrow(
      /mutlak/,
    );
  });
});

describe('runTool', () => {
  it('dry-run modunda komut çalıştırmaz, argv yazar', async () => {
    const output = await runTool('nmap_scan', { target: 'example.com', topPorts: 10 }, { scope, dryRun: true });
    expect(output).toStartWith('dry-run: nmap');
    expect(output).toContain('example.com');
  });

  it('nuclei dry-run modunda komut çalıştırmaz', async () => {
    const output = await runTool(
      'nuclei_scan',
      { target: 'example.com', severity: 'high' },
      { scope, dryRun: true },
    );
    expect(output).toStartWith('dry-run: nuclei');
    expect(output).toContain('high');
  });

  it('bilinmeyen aracı reddeder', async () => {
    await expect(runTool('rm_rf', {}, { scope, dryRun: true })).rejects.toThrow(/bilinmeyen/);
  });
});
