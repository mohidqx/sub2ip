# Changelog

All notable changes to sub2ip will be documented in this file.

## [1.2.0] - 2026-04-17

### Fixed

- **DNS Resolution Reliability** 
  - Switched to system DNS resolver by default for better compatibility
  - Resolves failures on diverse network configurations
  - Improves success rate across Windows, WSL, and Linux
  - Maintains backward compatibility with custom resolver flags (`-r`, `-rL`, `--rotate`)
  - Faster initial resolution due to reduced overhead

- **Output File Handling**
  - Fixed CSV output to save ALL DNS records (not just basic fields)
  - Added comprehensive column headers for complete data export
  - Improved file flushing for real-time output

### Added (6 New Advanced Features - All Enabled by Default)

- **Email Extraction** (`--emails`)
  - Automatically extract email addresses from MX and TXT DNS records
  - Regex-based email pattern matching
  - Automatic email deduplication
  - Shows email count in main output
  - Lists all extracted emails in verbose mode (`-v`)
  - Useful for: Email harvesting, OSINT, reconnaissance

- **IP Reputation Scoring** (`--reputation`)
  - Scores IP reputation on 0-100 scale
  - Factors considered: Private IPs, CDN/hosting ranges, suspicious patterns
  - Color-coded output: Green (>75), Yellow (50-75), Red (<50)
  - Helps identify: Blacklisted IPs, suspicious ranges, proxy services
  - Useful for: Security assessment, IP quality evaluation, threat detection

- **DNS Query Performance Metrics** (`--dns-metrics`)
  - Tracks total, successful, and failed DNS queries
  - Calculates: Average query time, fastest query, slowest query
  - All times in milliseconds (ms)
  - Displayed in summary section
  - Useful for: Resolver performance analysis, debugging, optimization

- **Individual DNS Query Timing** (`--dns-time`)
  - Shows query time for each domain resolution
  - Displayed in [XXms] format next to each result
  - Color-coded (light green) for visual scanning
  - Helps identify: Slow domains, resolver lag, performance bottlenecks

- **Domain Format Validation** (`--validate`)
  - Pre-validates domain format before DNS resolution
  - Checks: Length (1-253), dots, hyphens, valid character sets
  - Uses regex pattern matching for RFC compliance
  - Prevents: Invalid DNS queries, resolver waste, error logs
  - Displays: Yellow warnings for invalid domains

- **Service Fingerprinting** (`--services`)
  - Detects services running on resolved IPs
  - Default ports scanned: 21, 22, 25, 80, 443, 3306, 5432, 8080, 8443
  - Custom ports via `--ports` flag (e.g., `--ports 22,80,443`)
  - Method: TCP banner grabbing with 2-second timeout per port
  - Non-blocking parallel probes
  - Services detected: FTP, SSH, SMTP, HTTP/HTTPS, MySQL, PostgreSQL, RDP
  - Shows count in output, lists all in verbose mode
  - Useful for: Attack surface mapping, asset discovery, vulnerability assessment

- **Reverse Mode (IP → Domain Lookup)** (`--reverse` / `ip2sub` binary)
  - Two ways to enable reverse mode:
    1. **Auto-reverse via `ip2sub` binary** - Copy or symlink binary as `ip2sub`, it automatically works in reverse mode
    2. **Explicit flag** - Use `--reverse` flag: `sub2ip --reverse -d 8.8.8.8`
  - Finds domain names from IP addresses using reverse DNS (PTR records)
  - Works with all enrichment features (emails, reputation, GeoIP, services, etc.)
  - Same performance and feature set as forward mode (domain→IP)
  - Useful for: IP reconnaissance, domain discovery, reverse OSINT, IP block enumeration
  - Usage examples:
    - `ip2sub -d 1.1.1.1 -v` (auto-reverse from ip2sub binary)
    - `sub2ip --reverse -f ips.txt -o domains.txt` (explicit reverse mode)
    - `cat ips.txt | ip2sub --emails --reputation` (with enrichment)

- **Dual Output Formats** (NEW) - Save both TXT and CSV simultaneously
  - **TXT Format** (`-oT`): IP addresses only, one per line
    - Purpose: Piping to other tools (Nmap, Shodan, etc.)
    - Clean, simple format for automation
    - Use: `sub2ip -d target.com -oT ips.txt`
  - **CSV Format** (`-oC`): Complete data export with 27 columns
    - Purpose: Analysis, reporting, integration with ELK/Splunk/databases
    - Includes ALL DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR
    - Includes enrichment: Reputation score, emails, services, GeoIP, timestamps
    - Use: `sub2ip -d target.com -oC results.csv`
  - **Combined**: Generate both in one scan: `sub2ip -d target.com -oT ips.txt -oC results.csv`
  - Supports all other output formats: JSON (`-oJ`), Nmap (`-oN`), Masscan (`-oM`)
  - See [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md) for integration examples

- **Enhanced DNS Record Support** (Completes All Record Types)
  - SOA (Start of Authority) - Authority information
  - SRV (Service) - Service records for specific services
  - CAA (Certification Authority Authorization) - Certificate authority permissions
  - PTR (Pointer) - Reverse DNS records
  - All records now captured in CSV exports
  - Note: SOA, SRV, CAA require miekg/dns library for full functionality (currently placeholder)

### Changed
- **Default Behavior**: All 6 new features now enabled by default
  - Email extraction from DNS records
  - IP reputation scoring (0-100)
  - DNS query performance tracking
  - Individual query timing display
  - Domain format validation
  - Service detection on common ports
  - Note: Progress bar remains **disabled** by default (for clean output)

- **Output Format Enhanced** with new fields:
  - DNS timing: `[45ms]`
  - Reputation score: `[Rep:85]`
  - Email count: `[3 emails]`
  - Service count: `[2 services]`

- **Summary Report Enhanced**:
  - Now includes detailed DNS metrics section
  - Shows average/fastest/slowest query times
  - Lists success/failure statistics
  - More comprehensive performance analysis

### Behavior Changes
```
BEFORE (v1.1.0):
  sub2ip -f domains.txt
  → Basic output: [IP] domain [1.2.3.4]
  
AFTER (v1.2.0):
  sub2ip -f domains.txt
  → Rich output: [IP] domain [1.2.3.4] [45ms] [Rep:85] [2 services] [3 emails]
  → Plus detailed DNS metrics in summary
```

### Disable New Features
All new features can be disabled with `--no-*` flags:
- `--no-emails` - Skip email extraction
- `--no-reputation` - Skip reputation scoring
- `--no-dns-metrics` - Skip DNS metrics tracking
- `--no-dns-time` - Skip individual query timing
- `--no-validate` - Skip domain validation
- `--no-services` - Skip service detection

### Usage Examples

```bash
# All new features enabled (default)
sub2ip -f domains.txt

# With verbose output to see all details
sub2ip -f domains.txt -v

# Disable specific features
sub2ip -f domains.txt --no-emails --no-services

# Full security reconnaissance
sub2ip -d target.com --all-records --emails --reputation \
  --services --ports 22,80,443,3306 -v

# Email harvesting with validation
sub2ip -f subdomains.txt --validate --emails --mx --txt -v

# Performance analysis
sub2ip -f list.txt --dns-metrics --dns-time --summary -c 3000

# Service discovery
sub2ip -f domains.txt --services --ports 22,80,443,8080,3306

# Minimal output (disable new features)
sub2ip -f domains.txt --no-emails --no-reputation --no-dns-metrics \
  --no-dns-time --no-validate --no-services
```

### Technical Details

**New Config Fields:**
```go
ExtractEmails    bool   // Extract emails from DNS records
RepCheck         bool   // Check IP reputation
DNSMetrics       bool   // Track DNS query performance
ValidateDomains  bool   // Pre-validate domain format
ServiceDetect    bool   // Detect services on ports
ShowDNSTime      bool   // Show individual query times
```

**New Result Fields (JSON):**
```json
{
  "emails": ["admin@example.com"],
  "reputation_score": 85,
  "dns_query_ms": 45,
  "services": ["port-80", "port-443"]
}
```

### Performance Impact
- Email extraction: O(n) regex matching on DNS records
- Reputation scoring: O(1) simple logic
- DNS metrics: Atomic operations, negligible overhead
- Service detection: Non-blocking, parallelizable, configurable timeout

### Backward Compatibility
- ✅ All existing flags unchanged
- ✅ Output format backward compatible (new fields appended)
- ✅ JSON export includes new fields
- ✅ Can disable new features if needed
- ✅ No breaking changes

---

## [1.1.0] - 2026-04-17

### Added
- **Sticky Progress Bar**: Progress bar now stays at bottom of terminal while results scroll above (prevents output clutter)
- Auto-enable features by default for streamlined, fast usage
- New disable flags to turn off default features:
  - `--no-progress` - Disable sticky progress bar
  - `--no-summary` - Disable final summary output
  - `--no-stats` - Disable statistics tracking
  - `--no-all-records` - Disable all record types lookup
  - `--no-dedup` / `--no-deduplicate` - Disable deduplication
  - `--no-cdn` - Disable CDN detection
  - `--no-geo` / `--no-geoip` - Disable GeoIP lookup
  - `--no-asn-lookup` - Disable ASN lookup

### Changed
- **Breaking Change**: New default behavior with all features enabled:
  - Sticky progress bar (bottom of screen)
  - Summary statistics at end
  - Statistics tracking (resolved/failed counts)
  - All DNS record types (A, AAAA, MX, NS, TXT, CNAME)
  - Subdomain deduplication
  - CDN provider detection
  - GeoIP information retrieval
  - ASN lookup and tracking
- Clean output format by default: `[IP] domain [ip.address]` (no clutter)
- Output details only shown when explicitly requested via flags
- Terminal escape codes for clean progress bar rendering (`\033[2K\r` for line clearing)

### Behavior
- **Before v1.1**: `cat subs.txt | sub2ip` → Basic A record only
- **After v1.1**: `cat subs.txt | sub2ip` → Full resolution + progress bar at bottom + final stats

### Terminal Output
```
[IP] domain1.com [1.2.3.4]
[IP] domain2.com [5.6.7.8]
[IP] domain3.com [9.10.11.12]
█████████████░░░ 75% | 1500/2000 | Found: 825 | 1200/s
```

### Examples
```bash
# Fast bulk resolution (new default)
cat subs.txt | sub2ip

# With country/org enrichment
cat subs.txt | sub2ip --show-country --show-org

# Minimal output (disable features)
cat subs.txt | sub2ip --no-progress --no-summary --no-stats

# Verbose with all details
cat subs.txt | sub2ip -v
```

---

## [1.0.0] - Previous Release

### Features
- Subdomain to IP resolution
- Multiple DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR)
- CDN and Cloud provider detection
- GeoIP enrichment
- TLS and HTTP probing
- Wildcard detection
- Subdomain takeover detection
- DNS brute forcing
- Multiple output formats (JSON, CSV, Nmap, Masscan)
- Rate limiting and concurrency control
- Resolver rotation and custom resolvers support
