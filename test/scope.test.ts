import { describe, expect, it } from 'bun:test';
import {
  assertTarget,
  inScope,
  isPrivateHost,
  normalizeHost,
  parseScope,
  type Scope,
} from '../src/scope.ts';

const scope = (allowed: string[], allowPrivate = false): Scope => ({ allowed, allowPrivate });

describe('parseScope', () => {
  it('virgül/boşluk ayırır, protokol ve yolu temizler', () => {
    expect(parseScope('https://Example.com/path, *.test.dev  api.example.com')).toEqual([
      'example.com',
      '*.test.dev',
      'api.example.com',
    ]);
  });

  it('boş girdide boş dizi döner', () => {
    expect(parseScope(undefined)).toEqual([]);
    expect(parseScope('')).toEqual([]);
  });
});

describe('normalizeHost', () => {
  it('URL, host ve port biçimlerini kabul eder', () => {
    expect(normalizeHost('https://Example.com/a?b=1')).toBe('example.com');
    expect(normalizeHost('example.com:8443')).toBe('example.com');
    expect(normalizeHost('http://127.0.0.1:8080')).toBe('127.0.0.1');
  });

  it('geçersiz hedefi reddeder', () => {
    expect(() => normalizeHost('')).toThrow();
    expect(() => normalizeHost('ftp://example.com')).toThrow();
  });
});

describe('isPrivateHost', () => {
  it('yerel/özel aralıkları yakalar', () => {
    for (const host of ['localhost', '127.0.0.1', '10.1.2.3', '192.168.1.1', '172.20.0.1', '169.254.169.254', '::1', 'fd00::1']) {
      expect(isPrivateHost(host)).toBe(true);
    }
  });

  it('genel alan adlarını serbest bırakır', () => {
    expect(isPrivateHost('example.com')).toBe(false);
    expect(isPrivateHost('8.8.8.8')).toBe(false);
  });
});

describe('inScope', () => {
  it('apex ve alt alan adlarını eşler', () => {
    expect(inScope('example.com', ['example.com'])).toBe(true);
    expect(inScope('api.example.com', ['example.com'])).toBe(true);
    expect(inScope('example.com.evil.test', ['example.com'])).toBe(false);
  });

  it('wildcard yalnızca alt alan adlarını eşler', () => {
    expect(inScope('api.example.com', ['*.example.com'])).toBe(true);
    expect(inScope('example.com', ['*.example.com'])).toBe(false);
  });
});

describe('assertTarget', () => {
  it('kapsam içi hedefi döndürür', () => {
    expect(assertTarget('https://api.example.com/x', scope(['example.com']))).toBe('api.example.com');
  });

  it('kapsam dışı hedefi reddeder', () => {
    expect(() => assertTarget('https://evil.test', scope(['example.com']))).toThrow(/kapsam dışı/);
  });

  it('boş kapsamda çalışmayı reddeder', () => {
    expect(() => assertTarget('https://example.com', scope([]))).toThrow(/kapsam boş/);
  });

  it('özel adresi varsayılan olarak engeller', () => {
    expect(() => assertTarget('http://127.0.0.1', scope(['127.0.0.1']))).toThrow(/özel\/yerel/);
    expect(assertTarget('http://127.0.0.1', scope(['127.0.0.1'], true))).toBe('127.0.0.1');
  });

  it('metadata adresini her zaman engeller', () => {
    expect(() => assertTarget('http://169.254.169.254/latest', scope(['169.254.169.254'], true))).toThrow(
      /metadata/,
    );
  });
});
