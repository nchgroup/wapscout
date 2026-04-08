# wapscout

**wapscout** is a fast, full-featured CLI tool for web technology detection.  
It uses the [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) library to identify frameworks, CMSs, servers, analytics tools, and more than 1500 technologies.

```
  ██╗    ██╗ █████╗ ██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ██║    ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██║ █╗ ██║███████║██████╔╝███████╗██║     ██║   ██║██║   ██║   ██║
  ██║███╗██║██╔══██║██╔═══╝ ╚════██║██║     ██║   ██║██║   ██║   ██║
  ╚███╔███╔╝██║  ██║██║     ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝
                       Technology Detection CLI
```

---

## Features

- **High performance** — configurable concurrency for large-scale scans
- **Colorized output** — grouped by category with versions
- **Multiple formats** — `pretty`, `json`, `csv`, `plain`
- **stdin / file input** — accepts URLs via pipe or text file
- **Flexible TLS** — support for self-signed certificates
- **Proxy support** — HTTP and SOCKS5
- **Custom headers** — inject arbitrary HTTP headers
- **Statistical summary** — for batch scans
- **File output** — with `-o results.json`

---

## Installation

### Compiled binary (recommended)

```bash
git clone https://github.com/nchgroup/wapscout
cd wapscout
go build -o wapscout ./cmd
```

### Only run with `go run`

```bash
git clone https://github.com/nchgroup/wapscout
cd wapscout
go run ./cmd scan https://example.com
```

## Usage

### Scan a URL

```bash
./wapscout scan https://wordpress.com
```

```
  ────────────────────────────────────────────────────────────
  URL      : https://wordpress.com
  Status   : 200
  Duration : 842ms

  Technologies detected (7):

    ┌─ CMS
    └─ WordPress [v6.5]

    ┌─ JavaScript frameworks
    └─ React

    ┌─ Web servers
    ├─ Apache
    └─ Nginx

    ┌─ CDN
    └─ Cloudflare

  ────────────────────────────────────────────────────────────
```

### Multiple URLs

```bash
./wapscout scan https://github.com https://gitlab.com https://bitbucket.org
```

### JSON output

```bash
./wapscout scan https://github.com -f json
```

```json
{
  "url": "https://github.com",
  "final_url": "https://github.com/",
  "status_code": 200,
  "duration": "312ms",
  "technologies": {
    "Ruby on Rails": { "version": "", "categories": ["Web frameworks"] },
    "Cloudflare":    { "version": "", "categories": ["CDN"] }
  }
}
```

### CSV output

```bash
./wapscout scan https://github.com -f csv -o results.csv
```

### Read from stdin

```bash
echo "https://example.com" | ./wapscout scan -
cat urls.txt | ./wapscout scan -
```

### Batch scan (URL file)

```bash
./wapscout batch -i urls.txt -c 10 -f json -o results.json
```

```bash
  Loaded 50 URLs  |  concurrency: 10

  [████████████████░░░░░░░░░░░░░░]  27/50 (54%)

  Scan complete

  ── Summary ──────────────────────────────────
  Total scanned : 50
  With techs    : 44
  No techs      : 3
  Errors        : 3
  Unique techs  : 31
```

---

## Flags

### Shared (`scan` and `batch`)

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `pretty` | Output format: `pretty`, `json`, `csv`, `plain` |
| `--output` | `-o` | `stdout` | Output file |
| `--timeout` | `-t` | `15` | HTTP timeout in seconds |
| `--proxy` | `-p` | — | Proxy URL (e.g. `http://127.0.0.1:8080`) |
| `--insecure` | — | `false` | Ignore TLS errors |
| `--user-agent` | `-u` | wapscout/1.0 UA | Custom User-Agent |
| `--header` | `-H` | — | HTTP header (repeatable: `-H "X-Token: abc"`) |
| `--no-redirect` | — | `false` | Do not follow redirects |
| `--no-color` | — | `false` | Disable colors |
| `--show-meta` | — | `false` | Show response headers and categories |
| `--silent` | — | `false` | Suppress banner and informational messages |

### `scan` only

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--concurrency` | `-c` | `1` | Concurrency for multiple URLs |

### `batch` only

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--input` | `-i` | stdin | File with URLs (one per line) |
| `--concurrency` | `-c` | `5` | Maximum concurrent requests |

---

## URL file format

```text
# Comments starting with # are ignored
https://github.com
https://gitlab.com
https://wordpress.org
```

---

## Advanced examples

```bash
# Scan with proxy and custom headers
wapscout scan https://target.com \
  -p http://127.0.0.1:8080 \
  -H "Authorization: Bearer token123" \
  --insecure

# Pipeline: extract technologies as plain text
./wapscout scan https://example.com -f plain --silent

# Silent batch mode for script integration
./wapscout batch -i hosts.txt -f json --silent | jq '.[] | select(.technologies | length > 0)'

# Find WordPress in a list
./wapscout batch -i sites.txt -f plain --silent | grep "WordPress"
```

---

## Project structure

```
wapscout/
├── cmd/
│   └── main.go                  # Entry point + Cobra commands
├── internal/
│   ├── scanner/
│   │   └── scanner.go           # HTTP + wappalyzer logic
│   └── output/
│       ├── output.go            # Formatters (pretty/json/csv/plain)
│       └── csv_public.go        # Exported helper
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## License

MIT — free to use in offensive security, research, or automation projects.
