# eschaton-mcp

[![ci](https://github.com/Tarikdxd/eschaton-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Tarikdxd/eschaton-mcp/actions)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-stdio-6f42c1)](https://modelcontextprotocol.io)

nmap, httpx, ffuf ve sqlmap'i **MCP** üzerinden ajana açan küçük bir köprü. Amaç yeni bir tarayıcı yazmak değil; mevcut araçları **kapsam zorlaması, shell'siz çalıştırma ve denetlenebilir çıktı** ile bağlamak.

## Güvenlik modeli

Bu sunucu "her şeyi çalıştıran" bir kabuk değildir:

- **Kapsam zorunlu ve fail-closed.** `ESCHATON_MCP_SCOPE` boşsa tarama araçları çalışmaz.
- Hedef, kapsam listesindeki alan adlarıyla eşleşmezse araç reddeder.
- **Bulut metadata adresleri** (`169.254.169.254`, `metadata.google.internal`, `fd00:ec2::254`) her zaman engelli.
- **Özel/yerel adresler** (localhost, 10/8, 172.16/12, 192.168/16, link-local) varsayılan olarak engelli; yalnızca `ESCHATON_MCP_ALLOW_PRIVATE=1` ile açılır.
- Komutlar **shell kullanılmadan** (`execFile`, argüman dizisi) çalışır; kullanıcı girdisi argümana enjekte edilemez.
- Port, seviye, oran ve wordlist yolu gibi alanlar katı biçimde doğrulanır; wordlist mutlak yol olmalı ve 50 MB'ı aşamaz.
- `ESCHATON_MCP_DRY_RUN=1` ile hiçbir komut çalıştırılmaz, yalnızca üretilecek komut yazdırılır.

> Yalnızca **yazılı izin verdiğiniz** sistemlerde kullanın. Yetkisiz tarama suçtur.

## Gereksinimler

- [Bun](https://bun.sh) 1.2+
- Kullanmak istediğiniz araçlar `PATH` içinde: `nmap`, `httpx` (ProjectDiscovery), `ffuf`, `sqlmap`

## Kurulum

```sh
git clone https://github.com/Tarikdxd/eschaton-mcp.git
cd eschaton-mcp
bun install
```

Doğrudan çalıştırma:

```sh
ESCHATON_MCP_SCOPE=example.com bun src/index.ts
```

## MCP istemcisine ekleme

### OpenCode (`opencode.json`)

```json
{
  "mcp": {
    "eschaton": {
      "type": "local",
      "command": ["bun", "/mutlak/yol/eschaton-mcp/src/index.ts"],
      "enabled": true,
      "environment": {
        "ESCHATON_MCP_SCOPE": "example.com,*.example.com"
      }
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "eschaton": {
      "command": "bun",
      "args": ["/mutlak/yol/eschaton-mcp/src/index.ts"],
      "env": {
        "ESCHATON_MCP_SCOPE": "example.com"
      }
    }
  }
}
```

## Araçlar

| Araç | Argümanlar | Ne yapar |
| --- | --- | --- |
| `toolchain_status` | — | Kurulu araçları ve sürümlerini listeler (kapsam gerekmez) |
| `nmap_scan` | `target`, `ports?`, `topPorts?`, `serviceDetection?` | `nmap -Pn -T3` ile port/servis taraması |
| `httpx_probe` | `targets` (tek veya 1-20 dizi) | Durum kodu, başlık, teknoloji parmak izi |
| `ffuf_fuzz` | `url` (FUZZ içerir), `wordlist`, `method?`, `matchCodes?`, `rate?` | İçerik keşfi |
| `sqlmap_scan` | `url`, `level?` (1-3), `risk?` (1-2), `data?` | SQL enjeksiyonu doğrulama |

## Ortam değişkenleri

| Değişken | Varsayılan | Açıklama |
| --- | --- | --- |
| `ESCHATON_MCP_SCOPE` | boş | Virgül/boşluk ayrımlı izinli alan adları. `*.example.com` alt alan adları demektir. |
| `ESCHATON_MCP_ALLOW_PRIVATE` | kapalı | `1` ise özel/yerel adreslere izin verir (lab ağları için). |
| `ESCHATON_MCP_DRY_RUN` | kapalı | `1` ise komut çalıştırmaz, argv yazar. |

Komut satırından `--allow-private` bayrağı da kullanılabilir.

## Örnek akış

1. `toolchain_status` ile araçların kurulu olduğunu doğrula.
2. `nmap_scan` ile `example.com` üzerinde `topPorts: 100`.
3. `httpx_probe` ile açık HTTP servislerinin başlıklarını topla.
4. `ffuf_fuzz` ile `https://example.com/FUZZ` ve kendi wordlist'inle içerik keşfi yap.
5. Şüpheli parametrede `sqlmap_scan` (düşük `level`/`risk` ile başla).

## Geliştirme

```sh
bun install
bun test
bunx tsc --noEmit
ESCHATON_MCP_SCOPE=example.com ESCHATON_MCP_DRY_RUN=1 bun src/index.ts
```

## Lisans

MIT © 2026 Tarık Tozlu
