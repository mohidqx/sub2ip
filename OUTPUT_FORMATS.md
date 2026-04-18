# Sub2IP Output Formats (v1.2.0+)

## Two Output Modes for Every Scan

### 1️⃣ TXT Format (`-oT`) - IP List Only
**Purpose:** Simple IP addresses, one per line for piping to other tools

```bash
sub2ip -d target.com -oT ips.txt
```

**Output (ips.txt):**
```
142.250.202.238
2a00:1450:4018:812::200e
```

**Use Cases:**
- Feeding to other security tools
- Quick IP extraction
- Piping to Nmap: `cat ips.txt | nmap -iL -`
- Simple IP lists for reports

---

### 2️⃣ CSV Format (`-oC`) - Complete Data Export
**Purpose:** ALL data including all DNS records and hidden enrichment results

```bash
sub2ip -d target.com -oC results.csv
```

**CSV Structure (27 columns):**

| Category | Columns |
|----------|---------|
| **Domain Info** | domain, ips_count, ipv4, ipv6 |
| **DNS Records** | mx, ns, txt, cname, soa, srv, caa, ptr |
| **Geo/Network** | country, city, org, isp, asn, cdn, cloud |
| **HTTP/TLS** | http_status, http_title, tls_valid, wildcard |
| **Enrichment** | reputation_score, dns_query_ms, emails, services, timestamp |

---

## Comparison Table

| Aspect | TXT | CSV |
|--------|-----|-----|
| **Format** | Text (1 IP per line) | Comma-separated values |
| **Size** | Small | Larger (all data) |
| **DNS Records** | ❌ | ✅ MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR |
| **Enrichment** | ❌ | ✅ Reputation, Geo-IP, CDN, Cloud |
| **Emails** | ❌ | ✅ Extracted from DNS |
| **Services** | ❌ | ✅ Detected services |
| **Best For** | Tool piping | Analysis & reporting |

---

## Combined Usage Examples

```bash
# Generate both formats in one scan
sub2ip -d example.com -oT ips.txt -oC results.csv

# Scan with explicit output names
sub2ip -f domains.txt -oT all_ips.txt -oC complete_results.csv

# Scan and keep all format data
sub2ip -d target.com -oJ results.json -oT ips.txt -oC data.csv

# Silent mode - save files only, no terminal output
sub2ip -d target.com -oT ips.txt -oC results.csv -s

# Reverse mode with dual output
ip2sub -d 1.1.1.1 -oT resolved.txt -oC resolved.csv

# With increased timeout and retries
sub2ip -d slow.domain.com -oT ips.txt -oC data.csv -t 10 --retries 5
```

---

## CSV Column Details

### Domain & IP Data
- **domain**: The queried domain name
- **ips_count**: Number of resolved IPs
- **ipv4**: All IPv4 addresses (pipe-separated)
- **ipv6**: All IPv6 addresses (pipe-separated)

### DNS Records (All Record Types)
- **mx**: Mail exchange records
- **ns**: Nameserver records
- **txt**: TXT records (includes SPF, DKIM, DMARC)
- **cname**: Canonical name record
- **soa**: Start of authority record
- **srv**: Service records
- **caa**: Certification authority authorization
- **ptr**: Reverse DNS records

### Enrichment Data
- **reputation_score**: IP reputation 0-100 (higher=better)
- **emails**: Extracted email addresses from DNS
- **services**: Detected services on resolved IPs
- **country/city/org/isp/asn**: GeoIP information
- **cdn**: CDN provider detection
- **cloud**: Cloud provider detection (AWS, Azure, GCP, etc.)

### HTTP & Security
- **http_status**: HTTP status code
- **http_title**: HTTP response title
- **tls_valid**: TLS certificate validity (true/false)
- **wildcard**: Wildcard DNS detection

### Metadata
- **dns_query_ms**: DNS query time in milliseconds
- **timestamp**: Query timestamp (RFC3339)

---

## Sample CSV Row

```csv
google.com,2,142.250.202.238,2a00:1450:4018:812::200e,10 aspmx.l.google.com|20 alt1.aspmx.l.google.com,ns1.google.com|ns2.google.com,v=spf1 include:_spf.google.com,google.com.,,,dns.google.,US,Mountain View,Google,Google,AS15169,no,no,200,Google,true,false,98,160,support@google.com|security@google.com,port-80|port-443,2026-04-18T12:30:45Z
```

---

## Integration Examples

### Elasticsearch Import
```bash
# Convert CSV to NDJSON for Elasticsearch
sub2ip -f domains.txt -oC /tmp/results.csv
awk -F',' 'NR>1 {print "{\"domain\":\"" $1 "\", \"ips\":\"" $3 "\", \"country\":\"" $13 "\"}"}' /tmp/results.csv | curl -X POST "localhost:9200/_bulk" -d @-
```

### Splunk Import
```bash
# Use CSV directly with Splunk
sub2ip -d target.com -oC /tmp/data.csv
splunk add oneshot /tmp/data.csv -sourcetype dns_scan
```

### Quick Analysis
```bash
# Find all .edu domains with high reputation scores
sub2ip -f list.txt -oC data.csv
awk -F',' '$1 ~ /\.edu$/ && $25 > 90 {print $1, $25}' data.csv
```

---

## Version History

- **v1.2.0** (2026-04-18): Added dual output system (TXT + CSV)
  - TXT: Simple IP lists for tool chaining
  - CSV: Complete data export with all DNS records and enrichment
  - All DNS record types now captured (SOA, SRV, CAA)
  - Support for `-oT` and `-oC` flags
