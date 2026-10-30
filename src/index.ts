#!/usr/bin/env bun
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { scopeFromEnv, type Scope } from './scope.ts';
import { runTool } from './tools.ts';

const TOOLS = [
  {
    name: 'toolchain_status',
    description:
      'Kurulu güvenlik araçlarını (nmap, httpx, ffuf, sqlmap) ve sürümlerini listeler. Kapsam gerektirmez.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'nmap_scan',
    description:
      'Kapsam içindeki bir hedefte nmap port/servis taraması çalıştırır. Yetkili hedeflerde kullanın.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Alan adı veya IP' },
        ports: { type: 'string', description: 'Örn. 80,443,8000-8100' },
        topPorts: { type: 'integer', minimum: 1, maximum: 65535 },
        serviceDetection: { type: 'boolean' },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'httpx_probe',
    description: 'Kapsam içindeki URL/alan adlarının HTTP parmak izini (durum, başlık, teknoloji) toplar.',
    inputSchema: {
      type: 'object',
      properties: {
        targets: {
          oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' }, maxItems: 20 }],
        },
      },
      required: ['targets'],
      additionalProperties: false,
    },
  },
  {
    name: 'ffuf_fuzz',
    description:
      'Kapsam içindeki bir URL üzerinde ffuf ile içerik keşfi yapar. URL, FUZZ yer tutucusu içermelidir.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Örn. https://example.com/FUZZ' },
        wordlist: { type: 'string', description: 'Mutlak dosya yolu' },
        method: { type: 'string', enum: ['GET', 'POST'] },
        matchCodes: { type: 'string' },
        rate: { type: 'integer', minimum: 1, maximum: 200 },
      },
      required: ['url', 'wordlist'],
      additionalProperties: false,
    },
  },
  {
    name: 'sqlmap_scan',
    description: 'Kapsam içindeki tek bir URL üzerinde sqlmap ile SQL enjeksiyonu doğrular.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        level: { type: 'integer', minimum: 1, maximum: 3 },
        risk: { type: 'integer', minimum: 1, maximum: 2 },
        data: { type: 'string', description: 'POST gövdesi (en fazla 8 KB)' },
      },
      required: ['url'],
      additionalProperties: false,
    },
  },
] as const;

function scopeWithFlags(): Scope {
  const scope = scopeFromEnv();
  if (process.argv.includes('--allow-private')) scope.allowPrivate = true;
  return scope;
}

async function main(): Promise<void> {
  const scope = scopeWithFlags();
  const dryRun = process.env.ESCHATON_MCP_DRY_RUN === '1';
  if (scope.allowed.length === 0) {
    console.error('[eschaton-mcp] uyarı: ESCHATON_MCP_SCOPE boş; tarama araçları kapsam dışı hatası verecek.');
  }

  const server = new Server(
    { name: 'eschaton-mcp', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: rawArgs } = request.params;
    try {
      const output = await runTool(name, rawArgs, { scope, dryRun });
      return { content: [{ type: 'text', text: output }] };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `hata: ${(error as Error).message}` }],
        isError: true,
      };
    }
  });

  await server.connect(new StdioServerTransport());
  console.error('[eschaton-mcp] stdio üzerinde hazır');
}

void main().catch((error) => {
  console.error('[eschaton-mcp] başlatılamadı:', (error as Error).message);
  process.exit(1);
});
