// Kapsam ve hedef doğrulaması. Tüm araçlar buradan geçmeden komut çalıştırmaz.

export interface Scope {
  allowed: string[];
  allowPrivate: boolean;
}

const METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata',
  'fd00:ec2::254',
]);

export function parseScope(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(/[,\s]+/)
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean)
    .map((entry) => entry.replace(/^https?:\/\//, '').replace(/\/.*$/, ''));
}

export function normalizeHost(target: string): string {
  const value = target.trim();
  if (!value) throw new Error('hedef boş olamaz');
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error(`geçersiz hedef: ${target}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('yalnızca http/https hedefleri desteklenir');
  }
  return url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
}

export function isPrivateHost(host: string): boolean {
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === '::1') return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(host)) return true;
  if (/^fe80:/i.test(host)) return true;

  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return false;
  const [a, b] = [Number(match[1]), Number(match[2])];
  if ([a, b].some((part) => Number.isNaN(part))) return false;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

export function inScope(host: string, allowed: string[]): boolean {
  return allowed.some((entry) => {
    if (entry.startsWith('*.')) {
      return host.endsWith(`.${entry.slice(2)}`);
    }
    return host === entry || host.endsWith(`.${entry}`);
  });
}

export function assertTarget(target: string, scope: Scope): string {
  const host = normalizeHost(target);
  if (METADATA_HOSTS.has(host)) {
    throw new Error('bulut metadata adresi engelli');
  }
  if (scope.allowed.length === 0) {
    throw new Error('kapsam boş: ESCHATON_MCP_SCOPE ortam değişkenini tanımlayın');
  }
  if (!inScope(host, scope.allowed)) {
    throw new Error(`kapsam dışı hedef: ${host}`);
  }
  if (isPrivateHost(host) && !scope.allowPrivate) {
    throw new Error('özel/yerel adres engelli (açmak için ESCHATON_MCP_ALLOW_PRIVATE=1)');
  }
  return host;
}

export function scopeFromEnv(): Scope {
  return {
    allowed: parseScope(process.env.ESCHATON_MCP_SCOPE),
    allowPrivate: process.env.ESCHATON_MCP_ALLOW_PRIVATE === '1',
  };
}
