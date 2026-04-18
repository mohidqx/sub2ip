https://github.com/mohidqx/sub2ip/blob/main/interface.png
<p align="center">
  <b>sub2ip</b> — blazing fast subdomain → IP resolver<br>
  <code>@mohidqx</code>&nbsp;&nbsp;|&nbsp;&nbsp;<code>v1.2.0</code>
</p>

---

## Install

```bash
go install github.com/mohidqx/sub2ip@latest
```

## Quick Start

```bash
# stdin pipe (all defaults enabled: email extraction + reputation + DNS metrics + services + validation)
cat subs.txt | sub2ip

# file input
sub2ip -f subs.txt

# single domain
sub2ip -d target.com

# with enrichment details (country, org, cdn)
sub2ip -f subs.txt --show-country --show-org

# fast bulk with higher concurrency
sub2ip -f subs.txt -c 5000

# verbose mode (all details including emails and services)
sub2ip -f subs.txt -v

# disable progress bar if needed
sub2ip -f subs.txt --no-progress

# auto update
sub2ip -up
```

## � Output Formats (v1.2.0+)

**Generate TWO output files in one scan:**

```bash
# TXT format: IP addresses only (one per line)
# CSV format: ALL DNS records + enrichment data
sub2ip -d target.com -oT ips.txt -oC results.csv
```

**TXT Output** (`-oT`): Simple IP list for tool piping
```
142.250.202.238
2a00:1450:4018:812::200e
```

**CSV Output** (`-oC`): Complete dataset (27 columns)
- Domain info, IPv4/IPv6, DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR)
- Enrichment: Reputation score, extracted emails, detected services
- GeoIP: Country, City, Organization, ISP, ASN, CDN, Cloud provider
- Metadata: HTTP status, TLS validation, query time, timestamp

**See [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md) for complete documentation & integration examples**

---

## �🔄 Reverse Mode (IP → Domain Lookup)

Two ways to use reverse mode:

### Method 1: Using ip2sub Binary (Auto-Reverse)
When you have `ip2sub` binary (copy or symlink of `sub2ip`), it **automatically** works in reverse mode:

```bash
# single IP
ip2sub -d 8.8.8.8

# file input
ip2sub -f ips.txt -o domains.txt

# stdin pipe
cat ips.txt | ip2sub -v

# with enrichment (same features as sub2ip)
ip2sub -d 1.1.1.1 --show-country --show-org -v
```

### Method 2: Using --reverse Flag
Or use the `--reverse` flag explicitly with sub2ip:

```bash
# single IP
sub2ip --reverse -d 8.8.8.8

# file input
sub2ip --reverse -f ips.txt -o domains.txt

# stdin pipe
cat ips.txt | sub2ip --reverse
```

**Note:** All enrichment features work in both modes (email extraction, reputation, DNS metrics, services, GeoIP, etc.)

---

## 🔧 DNS Resolution (v1.2.0+)

**Fixed:** Improved DNS resolution reliability (v1.2.0+)

Starting with v1.2.0, the tool now uses **system DNS resolver by default** for better compatibility:
- ✅ Works with your system's default nameservers
- ✅ Respects `/etc/resolv.conf` configuration
- ✅ Higher success rate on diverse networks
- ✅ Better performance on Windows/WSL

**Custom DNS servers** still supported via flags:
```bash
# Use specific resolver
sub2ip -d target.com -r 8.8.8.8:53

# Rotate between multiple resolvers
sub2ip -f domains.txt -r 1.1.1.1:53 -r 8.8.8.8:53 --rotate

# Load resolvers from file
sub2ip -f domains.txt -rL resolvers.txt
```

---

## ✨ What's New in v1.2.0

**6 powerful new features enabled by default:**

1. **Email Extraction** (`--emails`)
   - Automatically extract email addresses from MX and TXT DNS records
   - Shows count in output: `[3 emails]`
   - Lists all emails in verbose mode (`-v`)
   
2. **IP Reputation Scoring** (`--reputation`)
   - Score IPs on 0-100 scale
   - Color-coded: Green (>75), Yellow (50-75), Red (<50)
   - Shows in output: `[Rep:85]`
   
3. **DNS Query Metrics** (`--dns-metrics`)
   - Tracks query performance: total, success, failures
   - Shows average/fastest/slowest query times
   - Detailed breakdown in summary section
   
4. **Individual Query Timing** (`--dns-time`)
   - Shows each query time: `[45ms]`
   - Helps identify performance bottlenecks
   
5. **Domain Validation** (`--validate`)
   - Pre-validates domain format before resolution
   - Prevents invalid DNS queries
   
6. **Service Fingerprinting** (`--services`)
   - Detects services on resolved IPs
   - Default ports: 21, 22, 25, 80, 443, 3306, 5432, 8080, 8443
   - Shows in output: `[2 services]`
   - Lists services in verbose mode: `[SERVICE] port-80`

## Default Features (v1.2.0+)

All of these are **enabled by default**:
- ✅ **Email Extraction** — Use `--no-emails` to disable
- ✅ **IP Reputation** — Use `--no-reputation` to disable  
- ✅ **DNS Metrics** — Use `--no-dns-metrics` to disable
- ✅ **DNS Timing** — Use `--no-dns-time` to disable
- ✅ **Domain Validation** — Use `--no-validate` to disable
- ✅ **Service Detection** — Use `--no-services` to disable
- ✅ **Summary Output** — Use `--no-summary` to disable  
- ✅ **Statistics Tracking** — Use `--no-stats` to disable
- ✅ **All DNS Records** (A, AAAA, MX, NS, TXT, CNAME) — Use `--no-all-records` to disable
- ✅ **Deduplication** — Use `--no-dedup` to disable
- ✅ **CDN Detection** — Use `--no-cdn` to disable
- ✅ **GeoIP Lookup** — Use `--no-geo` to disable
- ✅ **ASN Lookup** — Use `--no-asn-lookup` to disable

Note: Progress bar is **disabled by default** for clean output (use `--progress` to enable)

---

## All Flags

### Input
| Flag | Description |
|------|-------------|
| `-d, --domain` | Single domain |
| `-f, --file` | Input file (one domain per line) |
| stdin | Pipe via stdin |

### Output
| Flag | Description |
|------|-------------|
| `-o` | Output file |
| `-oJ` | JSON format |
| `-oC` | CSV format |
| `-oN` | Nmap-compatible |
| `-oM` | Masscan-compatible |
| `-oA` | All formats at once |
| `-s` | Silent (IPs only) |
| `-v` | Verbose |
| `-nc` | No color |
| `--no-banner` | Skip banner |
| `-ap` | Append to output |

### DNS
| Flag | Description |
|------|-------------|
| `-r` | Custom resolver (ip:port) |
| `-rL` | Resolver list file |
| `-ro` | Rotate through resolvers |
| `--udp` | UDP protocol (default) |
| `--tcp` | TCP protocol |
| `--doh <url>` | DNS over HTTPS |

### Performance
| Flag | Description |
|------|-------------|
| `-c` | Concurrency (default: 1500) |
| `-t` | Timeout in seconds (default: 2) |
| `--retries` | Retry count (default: 2) |
| `--rate` | Rate limit (req/sec) |
| `--delay` | Delay between queries (ms) |
| `--warmup` | Warmup resolver connections |

### Record Types
| Flag | Description |
|------|-------------|
| `-4` | IPv4 only (A records) |
| `-6` | IPv6 only (AAAA records) |
| `--mx` | MX records |
| `--ns` | NS records |
| `--txt` | TXT records |
| `--cname` | CNAME records |
| `--soa` | SOA records |
| `--srv` | SRV records |
| `--ptr` | Reverse DNS |
| `--caa` | CAA records |
| `-all, --all-records` | All record types (enabled by default) |
| `--no-all-records` | Disable all record types |

### Filtering
| Flag | Description |
|------|-------------|
| `--cidr` | Only IPs in CIDR |
| `--exclude-cidr` | Exclude IPs in CIDR |
| `--asn` | Filter by ASN |
| `--country` | Filter by country code |
| `--exclude-private` | Exclude RFC1918 IPs |
| `--exclude-public` | Exclude public IPs |
| `--exclude-cdn` | Exclude CDN IPs |
| `--only-wildcard` | Wildcard domains only |
| `--exclude-wildcard` | Skip wildcard domains |
| `--min-ttl` | Minimum TTL |
| `--max-ttl` | Maximum TTL |

### Enrichment
| Flag | Description |
|------|-------------|
| `--geo, --geoip` | GeoIP country/city (enabled by default) |
| `--no-geo` | Disable GeoIP |
| `--asn-lookup` | ASN info (enabled by default) |
| `--no-asn-lookup` | Disable ASN lookup |
| `--show-country` | Show country in output |
| `--show-org` | Show organization in output |
| `--reverse` | Reverse DNS per IP |
| `--whois` | WHOIS info |
| `--cdn` | CDN detection (enabled by default) |
| `--no-cdn` | Disable CDN detection |
| `--cloud` | Cloud provider (AWS/GCP/Azure/DO) |
| `--tls` | TLS certificate probe |
| `--http` | HTTP probe |
| `--https` | HTTPS probe |
| `-p` | Custom ports (80,443,8080) |
| `--port-scan` | Common port scan |

### HTTP Probing
| Flag | Description |
|------|-------------|
| `--title` | Page title |
| `--status-code` | HTTP status code |
| `--tech` | Web tech detection |
| `--follow-redirects` | Follow redirects |
| `--http-timeout` | HTTP timeout (default: 5s) |
| `-ua` | Custom User-Agent |
| `-H` | Custom header (repeatable) |

### IP Details
| Flag | Description |
|------|-------------|
| `--ip-type` | public/private/CDN |
| `--hostname` | Resolved hostname |
| `--org` | Organization |
| `--isp` | ISP name |
| `--city` | City |
| `--show-country` | Country code |
| `--latlong` | Lat/Long coords |
| `--timezone` | Timezone |
| `--rir` | ARIN/RIPE/APNIC etc. |

### Advanced Features (v1.2.0+)
| Flag | Description |
|------|-------------|
| `--emails` | Extract emails from DNS (enabled by default) |
| `--no-emails` | Disable email extraction |
| `--reputation` | IP reputation score 0-100 (enabled by default) |
| `--no-reputation` | Disable reputation scoring |
| `--dns-metrics` | Track DNS query metrics (enabled by default) |
| `--no-dns-metrics` | Disable DNS metrics |
| `--dns-time` | Show individual query times (enabled by default) |
| `--no-dns-time` | Disable query timing |
| `--validate` | Validate domain format (enabled by default) |
| `--no-validate` | Disable validation |
| `--services` | Detect services on IPs (enabled by default) |
| `--no-services` | Disable service detection |

### Advanced
| Flag | Description |
|------|-------------|
| `--dedup` | Deduplicate domains (enabled by default) |
| `--no-dedup` | Disable deduplication |
| `--sort` | Sort output A→Z |
| `--rsort` | Sort Z→A |
| `--wildcard` | Wildcard detection |
| `--takeover` | Subdomain takeover check |
| `--cf-ip` | Cloudflare IP detection |
| `--akamai` | Akamai IP detection |
| `--brute` | DNS brute force |
| `-w` | Wordlist for brute force |
| `--permute` | Domain permutation |
| `--permute-words` | Permutation words (comma-sep) |
| `--chunk` | Process in chunks of N |
| `--resume` | Resume from checkpoint |
| `--resume-file` | Checkpoint file |

### Stats & Display
| Flag | Description |
|------|-------------|
| `--stats` | Live statistics (enabled by default) |
| `--no-stats` | Disable statistics tracking |
| `--summary` | Final summary (enabled by default) |
| `--no-summary` | Disable summary output |
| `--progress` | Sticky progress bar (disabled by default) |
| `--no-progress` | Disable progress bar |
| `--count` | Resolved count |
| `--line-count` | Input line count |

### System
| Flag | Description |
|------|-------------|
| `-up` | Auto-update |
| `--version` | Show version |
| `--debug` | Debug mode |
| `-h` | Help |

---

## Examples

```bash
# All features enabled by default (v1.2.0)
cat subs.txt | sub2ip

# With enrichment details visible
cat subs.txt | sub2ip --show-country --show-org -v

# Minimal output (disable new features)
cat subs.txt | sub2ip --no-emails --no-reputation --no-services

# Verbose output with all details
cat subs.txt | sub2ip -v

# High concurrency + higher timeout
sub2ip -f subs.txt -c 5000 -t 5

# Email harvesting with DNS records
sub2ip -f subs.txt --emails --mx --txt -v -oJ results.json

# Security reconnaissance
sub2ip -d target.com --emails --reputation --services --ports 22,80,443,3306 -v

# Performance analysis
sub2ip -f subs.txt --dns-metrics --dns-time --summary -c 3000

# Service discovery with custom ports
sub2ip -f subs.txt --services --ports 22,80,443,8080,3306 -v

# Full HTTP recon
sub2ip -f subs.txt --http --https --title --status-code -v

# Takeover hunting
sub2ip -f subs.txt --cname -v

# IPv6 only
sub2ip -f subs.txt -6

# JSON export with all enrichments
sub2ip -f subs.txt -oJ -o results.json

# DNS brute force
sub2ip -d target.com --brute -w /usr/share/wordlists/subdomains.txt

# Exclude CDN, private IPs, sort output
sub2ip -f subs.txt --exclude-cdn --exclude-private --sort

# Custom resolvers + rotation
sub2ip -f subs.txt -rL resolvers.txt -ro -c 5000

# Silent mode (IPs only, minimal output)
sub2ip -f subs.txt -s --no-progress

# Masscan output
sub2ip -f subs.txt -s -oM -o targets.txt --no-progress
```

---

## Output Format

### Default Output (v1.2.0)
```
[IP] webserver.example.com                [203.0.113.45] [45ms] [Rep:85] [2 services] [3 emails]
[IP] api.example.com                      [203.0.113.50] [12ms] [Rep:92] [1 services] [1 emails]
[IP] cdn.example.com                      [203.0.113.60] [234ms] [Rep:45] [CDN:Cloudflare]
```

### Output Colors

| Color | Meaning |
|-------|---------|
| 🔵 Blue `[IP]` | Resolved domain |
| 🟢 Light Green `[45ms]` | DNS query time |
| 🟢 Green `[Rep:92]` | Good reputation (>75) |
| 🟡 Yellow `[Rep:65]` | Moderate reputation (50-75) |
| 🔴 Red `[Rep:35]` | Poor reputation (<50) |
| 🟢 Green `[2 services]` | Services found |
| 🔵 Cyan `[3 emails]` | Emails found |
| 🟠 Orange `[CDN:X]` | CDN provider |
| 🔵 Light Blue `[AWS/GCP/Azure]` | Cloud provider |
| 🟡 Yellow `[US]` | Country code |
| 🟣 Purple `[AS13335]` | ASN/Org |
| 🟢 Green `[200]` | HTTP 2xx |
| 🔴 Red `[404]` | HTTP 4xx/5xx |
| 🟢 Green `[TLS✓]` | Valid TLS cert |
| 🟣 Magenta `[WILDCARD]` | Wildcard domain |

---
https://github.com/mohidqx/sub2ip/blob/main/interface.png
## Built-in Resolvers

Includes 15 fast public resolvers: Google, Cloudflare, Quad9, OpenDNS, Verisign, AdGuard, Alternate DNS, CleanBrowsing — automatically rotated.

---

## CDN Detection

Detects: **Cloudflare**, **Akamai**, **Fastly**, **AWS CloudFront**

## Cloud Detection

Detects: **AWS**, **GCP**, **Azure**, **DigitalOcean**

## Service Detection (v1.2.0+)

Detects services on: FTP, SSH, SMTP, HTTP, HTTPS, MySQL, PostgreSQL, RDP

## Takeover Signatures

Checks 15+ services: GitHub Pages, Heroku, Shopify, Fastly, WPEngine, S3, CloudFront, Pantheon, Zendesk, Tumblr, Unbounce, Ghost, Webflow, Surge.sh, Bitbucket, Launchrock

---

<sub>Made with ❤️ by @mohidqx</sub>
