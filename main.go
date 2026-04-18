package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Version ─────────────────────────────────────────────────────────────────

const version = "1.2.0"
const repo = "github.com/mohidqx/sub2ip"

// Tool name (sub2ip or ip2sub based on argv[0])
var toolName = "sub2ip"

// ─── ANSI Colors ──────────────────────────────────────────────────────────────

const (
	reset      = "\033[0m"
	bold       = "\033[1m"
	dim        = "\033[2m"
	blue       = "\033[1;34m"
	cyan       = "\033[1;36m"
	green      = "\033[1;32m"
	yellow     = "\033[1;33m"
	red        = "\033[1;31m"
	darkRed    = "\033[38;5;88m"
	magenta    = "\033[1;35m"
	white      = "\033[1;37m"
	grey       = "\033[90m"
	orange     = "\033[38;5;208m"
	lightBlue  = "\033[38;5;117m"
	lightGreen = "\033[38;5;119m"
	purple     = "\033[38;5;141m"
	bgRed      = "\033[41m"
	bgGreen    = "\033[42m"
	bgBlue     = "\033[44m"
)

// ─── Tool Name Detection ──────────────────────────────────────────────────────

func getToolName() string {
	execName := filepath.Base(os.Args[0])
	// Remove .exe extension on Windows
	execName = strings.TrimSuffix(execName, ".exe")
	
	if strings.Contains(strings.ToLower(execName), "ip2sub") {
		return "ip2sub"
	}
	return "sub2ip"
}

// ─── Banner ───────────────────────────────────────────────────────────────────

func printBanner() {
	fmt.Println()
	if toolName == "ip2sub" {
		// Large IP2SUB banner from TAAG
		fmt.Printf("%s    _      ___              __  %s\n", cyan, reset)
		fmt.Printf("%s   (_)___ |__ \\ _______  __/ /_ %s\n", cyan, reset)
		fmt.Printf("%s  / / __ \\__/ // ___/ / / / __ \\ %s\n", cyan, reset)
		fmt.Printf("%s / / /_/ / __/(__  ) /_/ / /_/ / %s\n", cyan, reset)
		fmt.Printf("%s/_/ .___/____/____/\\__,_/_.___/  %s\n", cyan, reset)
		fmt.Printf("%s /_/                             %s\n", cyan, reset)
		fmt.Println()
		fmt.Printf("  %s@mohidqx%s  %sv%s%s\n",
			bold+darkRed, reset, grey, version, reset)
		fmt.Println()
	} else {
		// Original SUB2IP banner
		fmt.Printf("%s            __   ___   _ %s\n", cyan, reset)
		fmt.Printf("%s  ___ __ __/ /  |_  | (_)__ %s\n", cyan, reset)
		fmt.Printf("%s (_-</ // / _ \\/ __/ / / _ \\ %s\n", cyan, reset)
		fmt.Printf("%s/___/\\_,_/_.__/____// / .__/%s\n", cyan, reset)
		fmt.Printf("%s                   |_/_/     %s\n", cyan, reset)
		fmt.Println()
		fmt.Printf("  %s[%s%s%s]%s  %s@mohidqx%s  %sv%s%s\n",
			dim, magenta, "sub2ip", dim, reset, bold+darkRed, reset, grey, version, reset)
		fmt.Println()
	}
}

// ─── DNS Resolvers ────────────────────────────────────────────────────────────

var builtinResolvers = []string{
	"8.8.8.8:53",        // Google Primary
	"8.8.4.4:53",        // Google Secondary
	"1.1.1.1:53",        // Cloudflare Primary
	"1.0.0.1:53",        // Cloudflare Secondary
	"9.9.9.9:53",        // Quad9
	"149.112.112.112:53", // Quad9 Secondary
	"208.67.222.222:53", // OpenDNS Primary
	"208.67.220.220:53", // OpenDNS Secondary
	"64.6.64.6:53",      // Verisign Primary
	"64.6.65.6:53",      // Verisign Secondary
	"94.140.14.14:53",   // AdGuard Primary
	"94.140.15.15:53",   // AdGuard Secondary
	"76.76.19.19:53",    // Alternate DNS
	"76.223.122.150:53", // Alternate DNS Secondary
	"185.228.168.9:53",  // CleanBrowsing
}

// ─── Config Struct ─────────────────────────────────────────────────────────────

type Config struct {
	// Input
	InputFile  string
	Domain     string
	Stdin      bool

	// Output
	OutputFile   string
	OutputFormat string // text, json, csv, nmap, masscan
	Silent       bool
	NoColor      bool
	Verbose      bool
	NoASN        bool

	// DNS
	Resolvers       []string
	ResolverFile    string
	RotateResolvers bool
	UDP             bool
	TCP             bool
	DOH             string // DNS over HTTPS endpoint
	Protocol        string // udp, tcp, doh

	// Performance
	Concurrency int
	Timeout     int
	Retries     int
	RateLimit   int
	Delay       int

	// Lookup Types
	IPv4Only    bool
	IPv6Only    bool
	LookupMX    bool
	LookupNS    bool
	LookupTXT   bool
	LookupCNAME bool
	LookupSOA   bool
	LookupSRV   bool
	LookupCAA   bool
	LookupPTR   bool
	AllRecords  bool

	// Filtering
	FilterCIDR      string
	ExcludeCIDR     string
	FilterASN       string
	FilterCountry   string
	ExcludePrivate  bool
	ExcludePublic   bool
	ExcludeCDN      bool
	OnlyWildcard    bool
	ExcludeWildcard bool
	MinTTL          int
	MaxTTL          int

	// Enrichment
	GeoIP      bool
	ASNLookup  bool
	ReverseDNS bool
	WHOIS      bool
	CDNCheck   bool
	CloudCheck bool
	TLSProbe   bool
	HTTPProbe  bool
	HTTPSProbe bool
	Ports      []int
	PortScan   bool

	// HTTP Probing
	HTTPTitle    bool
	HTTPStatus   bool
	HTTPTech     bool
	FollowRedirs bool
	HTTPTimeout  int
	UserAgent    string
	Headers      []string

	// IP Info
	ShowIPType    bool
	ShowHostname  bool
	ShowOrg       bool
	ShowISP       bool
	ShowCity      bool
	ShowCountry   bool
	ShowLatLong   bool
	ShowTimezone  bool
	ShowRIR       bool

	// Stats
	Stats      bool
	Summary    bool
	Progress   bool
	Count      bool

	// ─── New Features ─────────────────────────────────────────────────────
	ExtractEmails    bool   // Extract emails from DNS records
	RepCheck         bool   // Check IP reputation
	DNSMetrics       bool   // Show DNS query performance metrics
	ValidateDomains  bool   // Pre-validate domains before resolution
	ServiceDetect    bool   // Detect services on open ports
	ShowDNSTime      bool   // Show individual DNS query times

	// Misc
	Update      bool
	Version     bool
	Help        bool
	Debug       bool
	NoBanner    bool
	Deduplicate bool
	SortOutput  bool
	ReverseSort bool
	LineCount   bool
	WarmUp      bool
	Stdin2File  string
	AppendMode  bool
	ReverseMode bool   // IP-to-domain reverse lookup mode (ip2sub)

	// Advanced
	Wildcard     bool
	TakeOver     bool
	CloudflareIP bool
	AkamaiCheck  bool
	FastzoneMap  bool
	DNSBrute     bool
	WordlistFile string
	Permute      bool
	PermuteWords []string
	ChunkSize    int
	Resume       bool
	ResumeFile   string
}

// ─── Result Struct ─────────────────────────────────────────────────────────────

type Result struct {
	Domain    string   `json:"domain"`
	IPs       []string `json:"ips,omitempty"`
	IPv4      []string `json:"ipv4,omitempty"`
	IPv6      []string `json:"ipv6,omitempty"`
	MX        []string `json:"mx,omitempty"`
	NS        []string `json:"ns,omitempty"`
	TXT       []string `json:"txt,omitempty"`
	CNAME     string   `json:"cname,omitempty"`
	SOA       []string `json:"soa,omitempty"`
	SRV       []string `json:"srv,omitempty"`
	CAA       []string `json:"caa,omitempty"`
	PTR       []string `json:"ptr,omitempty"`
	TTL       uint32   `json:"ttl,omitempty"`
	ASN       string   `json:"asn,omitempty"`
	Org       string   `json:"org,omitempty"`
	Country   string   `json:"country,omitempty"`
	City      string   `json:"city,omitempty"`
	ISP       string   `json:"isp,omitempty"`
	CDN       string   `json:"cdn,omitempty"`
	Cloud     string   `json:"cloud,omitempty"`
	Status    int      `json:"http_status,omitempty"`
	Title     string   `json:"http_title,omitempty"`
	TLSValid  bool     `json:"tls_valid,omitempty"`
	Wildcard  bool     `json:"wildcard,omitempty"`
	Resolver  string   `json:"resolver,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
	
	// ─── New Features ─────────────────────────────────────────────────────
	Emails        []string `json:"emails,omitempty"`           // Extracted emails
	Reputation    int      `json:"reputation_score,omitempty"` // IP reputation (0-100)
	DNSTime       int64    `json:"dns_query_ms,omitempty"`     // Query time in ms
	Services      []string `json:"services,omitempty"`         // Detected services
}

// ─── Stats Struct ──────────────────────────────────────────────────────────────

type Stats struct {
	mu          sync.Mutex
	Total       int64
	Resolved    int64
	Failed      int64
	StartTime   time.Time
	IPSet       map[string]bool
	CountrySet  map[string]int
	ASNSet      map[string]int
	CDNSet      map[string]int
	CloudSet    map[string]int
}

func newStats() *Stats {
	return &Stats{
		StartTime:  time.Now(),
		IPSet:      make(map[string]bool),
		CountrySet: make(map[string]int),
		ASNSet:     make(map[string]int),
		CDNSet:     make(map[string]int),
		CloudSet:   make(map[string]int),
	}
}

// ─── Global State ─────────────────────────────────────────────────────────────

var (
	cfg         Config
	stats       = newStats()
	results     []Result
	resultsMu   sync.Mutex
	resolverIdx int64
	outputFile  *os.File
	csvWriter   *csv.Writer
	jsonResults []Result
	seenDomains sync.Map
	seenIPs     sync.Map
)

// ─── CDN Ranges (simplified detection) ───────────────────────────────────────

var cdnRanges = map[string][]string{
	"Cloudflare": {"104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "172.64.", "172.65.", "172.66.", "172.67.", "162.158.", "198.41."},
	"Akamai":     {"184.24.", "184.25.", "184.26.", "184.27.", "184.28.", "184.29.", "184.30.", "184.31.", "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.", "23.39.", "23.40."},
	"Fastly":     {"151.101.", "199.27.", "23.235.", "103.244.", "103.245.", "103.246.", "103.247."},
	"AWS CF":     {"52.84.", "52.85.", "52.222.", "54.182.", "54.192.", "54.230.", "54.239.", "64.252.", "70.132.", "99.84.", "99.86.", "130.176.", "143.204.", "204.246.", "205.251.", "216.137."},
}

var cloudRanges = map[string][]string{
	"AWS":     {"52.", "54.", "34.", "35."},
	"GCP":     {"34.64.", "34.65.", "34.66.", "34.67.", "34.68.", "34.69.", "34.70.", "34.71.", "34.72.", "34.73.", "35.184.", "35.185.", "35.186.", "35.187.", "35.188.", "35.189.", "35.190."},
	"Azure":   {"13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.", "40.64.", "40.65.", "40.66.", "40.67.", "40.68.", "40.69.", "40.70.", "40.71.", "40.72.", "40.73.", "40.74."},
	"DigitalOcean": {"64.225.", "67.205.", "68.183.", "104.131.", "104.236.", "107.170.", "128.199.", "138.197.", "138.68.", "139.59.", "142.93.", "143.110.", "159.65.", "159.89.", "159.203."},
}

// ─── Flag Parsing ─────────────────────────────────────────────────────────────

func parseFlags() {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {

		// ─── Input ────────────────────────────────────────────────────────────
		case "-f", "--file":
			i++; if i < len(args) { cfg.InputFile = args[i] }
		case "-d", "--domain":
			i++; if i < len(args) { cfg.Domain = args[i] }
		case "-l", "--list":
			i++; if i < len(args) { cfg.InputFile = args[i] }

		// ─── Output ───────────────────────────────────────────────────────────
		case "-o", "--output":
			i++; if i < len(args) { cfg.OutputFile = args[i] }
		case "-oJ", "--json":
			cfg.OutputFormat = "json"
			i++; if i < len(args) { cfg.OutputFile = args[i] }
		case "-oC", "--csv":
			cfg.OutputFormat = "csv"
			i++; if i < len(args) { cfg.OutputFile = args[i] }
		case "-oT":
			cfg.OutputFormat = "txt"
			i++; if i < len(args) { cfg.OutputFile = args[i] }
		case "-oN", "--nmap":
			cfg.OutputFormat = "nmap"
			i++; if i < len(args) { cfg.OutputFile = args[i] }
		case "-oM", "--masscan":
			cfg.OutputFormat = "masscan"
			i++; if i < len(args) { cfg.OutputFile = args[i] }
		case "-oA", "--output-all":
			cfg.OutputFormat = "all"
			i++; if i < len(args) { cfg.OutputFile = args[i] }
		case "-s", "--silent":
			cfg.Silent = true
		case "-nc", "--no-color":
			cfg.NoColor = true
		case "-v", "--verbose":
			cfg.Verbose = true
		case "--no-banner":
			cfg.NoBanner = true
		case "-ap", "--append":
			cfg.AppendMode = true

		// ─── DNS ──────────────────────────────────────────────────────────────
		case "-r", "--resolver":
			i++; if i < len(args) { cfg.Resolvers = append(cfg.Resolvers, args[i]) }
		case "-rL", "--resolver-list":
			i++; if i < len(args) { cfg.ResolverFile = args[i] }
		case "-ro", "--rotate":
			cfg.RotateResolvers = true
		case "--udp":
			cfg.Protocol = "udp"
		case "--tcp":
			cfg.Protocol = "tcp"
		case "--doh":
			i++; if i < len(args) { cfg.DOH = args[i]; cfg.Protocol = "doh" }

		// ─── Performance ──────────────────────────────────────────────────────
		case "-c", "--concurrency":
			i++; if i < len(args) { cfg.Concurrency, _ = strconv.Atoi(args[i]) }
		case "-t", "--timeout":
			i++; if i < len(args) { cfg.Timeout, _ = strconv.Atoi(args[i]) }
		case "--retries":
			i++; if i < len(args) { cfg.Retries, _ = strconv.Atoi(args[i]) }
		case "--rate":
			i++; if i < len(args) { cfg.RateLimit, _ = strconv.Atoi(args[i]) }
		case "--delay":
			i++; if i < len(args) { cfg.Delay, _ = strconv.Atoi(args[i]) }

		// ─── Record Types ─────────────────────────────────────────────────────
		case "-4", "--ipv4":
			cfg.IPv4Only = true
		case "-6", "--ipv6":
			cfg.IPv6Only = true
		case "--mx":
			cfg.LookupMX = true
		case "--ns":
			cfg.LookupNS = true
		case "--txt":
			cfg.LookupTXT = true
		case "--cname":
			cfg.LookupCNAME = true
		case "--soa":
			cfg.LookupSOA = true
		case "--srv":
			cfg.LookupSRV = true
		case "--ptr":
			cfg.LookupPTR = true
		case "--caa":
			cfg.LookupCAA = true
		case "-all", "--all-records":
			cfg.AllRecords = true
		case "--no-all-records":
			cfg.AllRecords = false

		// ─── Filtering ────────────────────────────────────────────────────────
		case "--cidr":
			i++; if i < len(args) { cfg.FilterCIDR = args[i] }
		case "--exclude-cidr":
			i++; if i < len(args) { cfg.ExcludeCIDR = args[i] }
		case "--asn":
			i++; if i < len(args) { cfg.FilterASN = args[i] }
		case "--country":
			i++; if i < len(args) { cfg.FilterCountry = args[i] }
		case "--exclude-private":
			cfg.ExcludePrivate = true
		case "--exclude-public":
			cfg.ExcludePublic = true
		case "--exclude-cdn":
			cfg.ExcludeCDN = true
		case "--only-wildcard":
			cfg.OnlyWildcard = true
		case "--exclude-wildcard":
			cfg.ExcludeWildcard = true
		case "--min-ttl":
			i++; if i < len(args) { cfg.MinTTL, _ = strconv.Atoi(args[i]) }
		case "--max-ttl":
			i++; if i < len(args) { cfg.MaxTTL, _ = strconv.Atoi(args[i]) }

		// ─── Enrichment ───────────────────────────────────────────────────────
		case "--geo", "--geoip":
			cfg.GeoIP = true
		case "--no-geo", "--no-geoip":
			cfg.GeoIP = false
		case "--asn-lookup":
			cfg.ASNLookup = true
		case "--no-asn-lookup":
			cfg.ASNLookup = false
		case "--rdns":
			cfg.ReverseDNS = true
		case "--no-rdns":
			cfg.ReverseDNS = false
		case "--whois":
			cfg.WHOIS = true
		case "--cdn":
			cfg.CDNCheck = true
		case "--no-cdn":
			cfg.CDNCheck = false
		case "--cloud":
			cfg.CloudCheck = true
		case "--tls":
			cfg.TLSProbe = true
		case "--http":
			cfg.HTTPProbe = true
		case "--https":
			cfg.HTTPSProbe = true
		case "-p", "--ports":
			i++; if i < len(args) {
				for _, p := range strings.Split(args[i], ",") {
					port, _ := strconv.Atoi(strings.TrimSpace(p))
					if port > 0 { cfg.Ports = append(cfg.Ports, port) }
				}
			}
		case "--port-scan":
			cfg.PortScan = true

		// ─── HTTP Details ─────────────────────────────────────────────────────
		case "--title":
			cfg.HTTPTitle = true
		case "--status-code":
			cfg.HTTPStatus = true
		case "--tech":
			cfg.HTTPTech = true
		case "--follow-redirects":
			cfg.FollowRedirs = true
		case "--http-timeout":
			i++; if i < len(args) { cfg.HTTPTimeout, _ = strconv.Atoi(args[i]) }
		case "-ua", "--user-agent":
			i++; if i < len(args) { cfg.UserAgent = args[i] }
		case "-H", "--header":
			i++; if i < len(args) { cfg.Headers = append(cfg.Headers, args[i]) }

		// ─── IP Info ──────────────────────────────────────────────────────────
		case "--ip-type":
			cfg.ShowIPType = true
		case "--hostname":
			cfg.ShowHostname = true
		case "--org":
			cfg.ShowOrg = true
		case "--isp":
			cfg.ShowISP = true
		case "--city":
			cfg.ShowCity = true
		case "--show-country":
			cfg.ShowCountry = true
		case "--latlong":
			cfg.ShowLatLong = true
		case "--timezone":
			cfg.ShowTimezone = true
		case "--rir":
			cfg.ShowRIR = true

		// ─── Stats & Display ──────────────────────────────────────────────────
		case "--stats":
			cfg.Stats = true
		case "--no-stats":
			cfg.Stats = false
		case "--summary":
			cfg.Summary = true
		case "--no-summary":
			cfg.Summary = false
		case "--progress":
			cfg.Progress = true
		case "--no-progress":
			cfg.Progress = false
		case "--count":
			cfg.Count = true
		case "--line-count":
			cfg.LineCount = true
			
		// ─── New Features ─────────────────────────────────────────────────────
		case "--emails":
			cfg.ExtractEmails = true
		case "--reputation":
			cfg.RepCheck = true
		case "--dns-metrics":
			cfg.DNSMetrics = true
		case "--validate":
			cfg.ValidateDomains = true
		case "--services":
			cfg.ServiceDetect = true
		case "--dns-time":
			cfg.ShowDNSTime = true

		// ─── Advanced ─────────────────────────────────────────────────────────
		case "--dedup", "--deduplicate":
			cfg.Deduplicate = true
		case "--no-dedup", "--no-deduplicate":
			cfg.Deduplicate = false
		case "--sort":
			cfg.SortOutput = true
		case "--rsort":
			cfg.ReverseSort = true
		case "--wildcard":
			cfg.Wildcard = true
		case "--takeover":
			cfg.TakeOver = true
		case "--cf-ip":
			cfg.CloudflareIP = true
		case "--akamai":
			cfg.AkamaiCheck = true
		case "--brute":
			cfg.DNSBrute = true
		case "-w", "--wordlist":
			i++; if i < len(args) { cfg.WordlistFile = args[i] }
		case "--permute":
			cfg.Permute = true
		case "--permute-words":
			i++; if i < len(args) { cfg.PermuteWords = strings.Split(args[i], ",") }
		case "--chunk":
			i++; if i < len(args) { cfg.ChunkSize, _ = strconv.Atoi(args[i]) }
		case "--resume":
			cfg.Resume = true
		case "--resume-file":
			i++; if i < len(args) { cfg.ResumeFile = args[i] }
		case "--warmup":
			cfg.WarmUp = true

		// ─── System ───────────────────────────────────────────────────────────
		case "-up", "--update":
			cfg.Update = true
		case "--version":
			cfg.Version = true
		case "-h", "--help":
			cfg.Help = true
		case "--debug":
			cfg.Debug = true
		case "--reverse", "--ip2sub", "-R":
			cfg.ReverseMode = true
		case "--no-asn":
			cfg.NoASN = true

		default:
			// Positional domain argument
			if !strings.HasPrefix(args[i], "-") && cfg.Domain == "" {
				cfg.Domain = args[i]
			}
		}
	}

	// Defaults
	if cfg.Concurrency == 0 { cfg.Concurrency = 1500 }
	if cfg.Timeout == 0 { cfg.Timeout = 5 }    // Increased from 2 to 5 seconds
	if cfg.Retries == 0 { cfg.Retries = 3 }    // Increased from 2 to 3 retries
	if cfg.HTTPTimeout == 0 { cfg.HTTPTimeout = 5 }
	if cfg.Protocol == "" { cfg.Protocol = "udp" }
	// Empty resolvers list to force system resolver
	if len(cfg.Resolvers) == 0 { cfg.Resolvers = []string{} }
	if cfg.UserAgent == "" { cfg.UserAgent = "Mozilla/5.0 sub2ip/" + version }

	// ─── Auto-Enable Features by Default ───────────────────────────────────
	cfg.Progress = false      // Disable progress bar by default (use --progress to enable)
	cfg.Summary = true        // Show summary stats at end
	cfg.Stats = true          // Track statistics
	cfg.AllRecords = true     // Resolve all record types (A, AAAA, MX, NS, TXT, CNAME)
	cfg.Deduplicate = true    // Remove duplicate subdomains
	cfg.CDNCheck = true       // Detect CDN providers
	cfg.GeoIP = true          // Resolve GeoIP information
	cfg.ASNLookup = true      // Resolve ASN information
	cfg.ExtractEmails = true  // Extract emails from DNS records
	cfg.RepCheck = true       // Check IP reputation
	cfg.DNSMetrics = true     // Track DNS query performance
	cfg.ValidateDomains = true // Pre-validate domain format
	cfg.ServiceDetect = true  // Detect services on ports
	cfg.ShowDNSTime = true    // Show individual DNS query times
}

// ─── Help ─────────────────────────────────────────────────────────────────────

func printHelp() {
	var desc, usageNormal, usageReverse string
	var inputSection string
	if toolName == "ip2sub" {
		desc = "IP to subdomain reverse resolver — blazing fast, feature-rich"
		usageNormal = "ip2sub"
		usageReverse = "ip2sub"
		inputSection = `  -d,  --domain <ip>              Single IP address to resolve
  -f,  --file <file>             File with IP addresses (one per line)
  -l,  --list <file>             Alias for --file
       stdin                     Pipe IPs via stdin
       
  (Reverse mode is automatically enabled - no need for --reverse flag)`
	} else {
		desc = "Sub-domain to IP resolver • IP to subdomain reverse lookup — blazing fast, feature-rich"
		usageNormal = "sub2ip"
		usageReverse = "sub2ip --reverse"
		inputSection = `  -d,  --domain <domain>          Single domain or IP to resolve
  -f,  --file <file>             File with domains/IPs (one per line)
  -l,  --list <file>             Alias for --file
       stdin                     Pipe domains/IPs via stdin
  -R,  --reverse, --ip2sub        Reverse lookup mode (IP → Domain)
                                 Use with -d, -f, or stdin with IPs`
	}
	fmt.Printf("%s%s%s\n\n", bold+white, desc, reset)
	fmt.Printf("%s%sUSAGE%s\n", bold, white, reset)
	if toolName == "ip2sub" {
		fmt.Printf("  %s [flags]    (IP → Domain reverse lookup)\n\n", usageNormal)
	} else {
		fmt.Printf("  %s [flags]              (Domain → IP mode)\n", usageNormal)
		fmt.Printf("  %s [flags]    (IP → Domain reverse mode)\n\n", usageReverse)
	}

	sections := []struct{ title, content string }{
		{"INPUT", inputSection},

		{"OUTPUT", `  -o,  --output <file>            Write output to file
  -oJ, --json                    Output in JSON format
  -oC, --csv                     Output in CSV format
  -oN, --nmap                    Nmap-compatible output
  -oM, --masscan                 Masscan-compatible output
  -oA, --output-all              Write all formats simultaneously
  -s,  --silent                  Silent mode (IPs only)
  -v,  --verbose                 Verbose output with all details
  -nc, --no-color                Disable colored output
       --no-banner               Skip banner
  -ap, --append                  Append to output file`},

		{"DNS", `  -r,  --resolver <ip:port>       Custom DNS resolver
  -rL, --resolver-list <file>    File with resolvers
  -ro, --rotate                  Rotate through resolvers
       --udp                     Use UDP protocol (default)
       --tcp                     Use TCP protocol
       --doh <url>               DNS over HTTPS endpoint`},

		{"PERFORMANCE", `  -c,  --concurrency <int>        Goroutine workers (default: 1500)
  -t,  --timeout <secs>          Per-query timeout (default: 2)
       --retries <int>           Retry failed queries (default: 2)
       --rate <int>              Rate limit requests/sec
       --delay <ms>              Delay between queries (ms)
       --warmup                  Warmup resolver connections first`},

		{"RECORD TYPES", `  -4,  --ipv4                     Resolve IPv4 only (A records)
  -6,  --ipv6                     Resolve IPv6 only (AAAA records)
       --mx                      Lookup MX records
       --ns                      Lookup NS records
       --txt                     Lookup TXT records
       --cname                   Lookup CNAME records
       --soa                     Lookup SOA records
       --srv                     Lookup SRV records
       --ptr                     Reverse DNS lookup
       --caa                     Lookup CAA records
  -all,--all-records             Lookup all record types`},

		{"FILTERING", `       --cidr <cidr>              Only show IPs in CIDR range
       --exclude-cidr <cidr>     Exclude IPs in CIDR range
       --asn <asn>               Filter by ASN
       --country <cc>            Filter by country code (e.g., US)
       --exclude-private         Exclude RFC1918/private IPs
       --exclude-public          Exclude public IPs
       --exclude-cdn             Exclude CDN IPs
       --only-wildcard           Show only wildcard domains
       --exclude-wildcard        Exclude wildcard domains
       --min-ttl <int>           Minimum TTL filter
       --max-ttl <int>           Maximum TTL filter`},

		{"ENRICHMENT", `       --geo, --geoip             Add GeoIP country/city info
       --asn-lookup              Add ASN information
       --reverse, --rdns         Reverse DNS lookup for each IP
       --whois                   WHOIS IP range info
       --cdn                     Detect CDN provider
       --cloud                   Detect cloud provider (AWS/GCP/Azure)
       --tls                     TLS certificate probe
       --http                    HTTP probe (port 80)
       --https                   HTTPS probe (port 443)
  -p,  --ports <ports>          Custom port list (e.g., 80,443,8080)
       --port-scan               Scan common ports`},

		{"HTTP PROBING", `       --title                   Grab HTTP page title
       --status-code             Show HTTP status code
       --tech                    Detect web technologies
       --follow-redirects        Follow HTTP redirects
       --http-timeout <secs>     HTTP probe timeout (default: 5)
  -ua, --user-agent <string>     Custom User-Agent string
  -H,  --header <header>         Add custom HTTP header (repeatable)`},

		{"IP DETAILS", `       --ip-type                 Show IP type (public/private/CDN)
       --hostname                Show resolved hostname
       --org                     Show organization name
       --isp                     Show ISP name
       --city                    Show city
       --show-country            Show country
       --latlong                 Show latitude/longitude
       --timezone                Show timezone
       --rir                     Show RIR (ARIN/RIPE/APNIC etc.)`},

		{"ADVANCED", `       --dedup, --deduplicate    Deduplicate domains before resolving
       --sort                    Sort output alphabetically
       --rsort                   Reverse sort output
       --wildcard                Detect wildcard DNS
       --takeover                Check for subdomain takeover
       --cf-ip                   Detect Cloudflare IPs
       --akamai                  Detect Akamai IPs
       --brute                   DNS brute force mode
  -w,  --wordlist <file>         Wordlist for brute force
       --permute                 Generate domain permutations
       --permute-words <words>   Words for permutation (comma-sep)
       --chunk <int>             Process in chunks of N
       --resume                  Resume from last checkpoint
       --resume-file <file>      Checkpoint file path`},

		{"STATISTICS", `       --stats                   Show live statistics
       --summary                 Show final summary
       --progress                Show progress bar
       --count                   Show total resolved count
       --line-count              Show input line count
       
       --dns-metrics             Track DNS query performance metrics
       --dns-time                Show individual DNS query times
       --emails                  Extract email addresses from DNS records
       --reputation              Score IP reputation (0-100)
       --validate                Validate domain format before resolution
       --services                Detect services on resolved IPs`},

		{"SYSTEM", `  -up, --update                  Auto-update to latest version
       --version                 Show version
       --debug                   Debug mode
       --no-asn                  Skip ASN info
  -h,  --help                    Show this help`},
	}

	for _, s := range sections {
		fmt.Printf("%s%s%s\n", bold+yellow, s.title, reset)
		fmt.Printf("%s%s%s\n\n", grey, s.content, reset)
	}

	fmt.Printf("%s%sEXAMPLES%s\n", bold, white, reset)
	fmt.Printf("%s", grey)
	
	if toolName == "ip2sub" {
		// Show only reverse mode examples for ip2sub
		examples := []string{
			"-d 8.8.8.8",
			"-d 1.1.1.1 -v",
			"-f ips.txt",
			"-f ips.txt -o domains.txt",
			"-d 8.8.4.4 --show-country --show-org",
			"-f ips.txt -c 3000 --geo --cdn --cloud",
			"-f ips.txt --emails --reputation -v",
			"-f ips.txt -oJ -o domains.json",
			"-f ips.txt --all-records --dns-metrics",
			"-f ips.txt --services --ports 80,443,22",
			"-f ips.txt --validate --reputation",
		}
		for _, e := range examples {
			fmt.Printf("  ip2sub %s\n", e)
		}
		// Add piped examples
		fmt.Printf("  cat ips.txt | ip2sub\n")
		fmt.Printf("  cat ips.txt | ip2sub --emails --reputation -v\n")
	} else {
		// Show both forward and reverse mode examples for sub2ip
		examples := []string{
			"-f subs.txt -o resolved.txt",
			"-d target.com --all-records -v",
			"-f subs.txt -c 3000 --geo --cdn --cloud",
			"-f subs.txt -oJ --summary --stats",
			"--reverse -d 8.8.8.8 -v",
			"--reverse -f iplist.txt -o domains.txt",
			"-f subs.txt --http --title --status-code",
			"-f subs.txt --exclude-private --exclude-cdn",
			"-f subs.txt -6 --ipv6",
			"-f subs.txt --wildcard --takeover",
			"-f subs.txt --brute -w wordlist.txt",
			"-f subs.txt --tls --ports 443,8443",
			"-d target.com --mx --ns --txt",
			"-f subs.txt --asn-lookup --org --isp",
			"-f subs.txt --sort --dedup -oC -o out.csv",
			"-f subs.txt --cidr 10.0.0.0/8",
			"-f subs.txt --emails --dns-metrics -v",
			"-f subs.txt --validate --reputation --dns-time",
			"-f subs.txt --services --ports 80,443,22",
			"-up",
		}
		for _, e := range examples {
			fmt.Printf("  sub2ip %s\n", e)
		}
		// Add piped examples
		fmt.Printf("  cat subs.txt | sub2ip\n")
		fmt.Printf("  cat ips.txt | sub2ip --reverse\n")
		fmt.Printf("  cat ips.txt | sub2ip --reverse --emails --reputation -v\n")
	}
	fmt.Printf("%s\n", reset)
}

// ─── Email Extraction from DNS Records ────────────────────────────────────

func extractEmails(mxRecords, txtRecords []string) []string {
	var emails []string
	emailRe := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	
	// Check MX records
	for _, mx := range mxRecords {
		if found := emailRe.FindStringSubmatch(mx); found != nil {
			emails = append(emails, found[0])
		}
	}
	
	// Check TXT records (SPF, DKIM, etc.)
	for _, txt := range txtRecords {
		if found := emailRe.FindAllString(txt, -1); found != nil {
			emails = append(emails, found...)
		}
	}
	
	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, e := range emails {
		if !seen[e] {
			seen[e] = true
			unique = append(unique, e)
		}
	}
	return unique
}

// ─── IP Reputation Scoring ────────────────────────────────────────────────

func scoreReputation(ip string) int {
	// Basic reputation scoring (0-100, lower is worse)
	score := 100
	
	// Penalize private IPs
	if isPrivateIP(ip) { return 50 }
	
	// Penalize known CDN/hosting IPs (often used for abuse)
	for _, cidr := range []string{"52.", "54.", "34.", "35.", "104.16.", "172.64."} {
		if strings.HasPrefix(ip, cidr) { score -= 10 }
	}
	
	// Check for suspicious patterns
	octets := strings.Split(ip, ".")
	if len(octets) == 4 {
		// Penalize IPs ending in .0 or .255 (broadcast-like)
		if octets[3] == "0" || octets[3] == "255" { score -= 15 }
		// Penalize very low or very high octets
		for i, octet := range octets {
			val, _ := strconv.Atoi(octet)
			if val < 10 || val > 240 { score -= 2 }
			if i == 0 && (val < 8 || val > 223) { score -= 5 } // Invalid first octet
		}
	}
	
	if score < 0 { score = 0 }
	return score
}

// ─── Service Fingerprinting ───────────────────────────────────────────────

var servicePatterns = map[int][]string{
	21:    {"220", "331", "530"},           // FTP
	22:    {"SSH-2.0", "SSH-1.99"},         // SSH
	25:    {"220", "ESMTP"},                // SMTP
	80:    {"HTTP/", "Server:"},            // HTTP
	443:   {"HTTP/"},                       // HTTPS
	3306:  {"mysql", "5.7", "8.0"},        // MySQL
	5432:  {"PostgreSQL"},                  // PostgreSQL
	3389:  {"RDP"},                         // RDP
	8080:  {"HTTP/", "Server:"},           // HTTP Alternate
	8443:  {"HTTP/"},                       // HTTPS Alternate
}

func detectService(ip string, port int) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil { return "" }
	defer conn.Close()
	
	// Send banner request
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	banner := make([]byte, 256)
	n, _ := conn.Read(banner)
	bannerStr := string(banner[:n])
	
	// Try to match service
	for service, patterns := range servicePatterns {
		if service == port {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToUpper(bannerStr), strings.ToUpper(pattern)) {
					return fmt.Sprintf("port-%d", port)
				}
			}
		}
	}
	
	return ""
}

// ─── DNS Query Timing ─────────────────────────────────────────────────────

func resolveDomainTimed(domain string) ([]string, []string, int64, error) {
	start := time.Now()
	var ipv4s, ipv6s []string
	var lastErr error

	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		var ips []string
		var err error
		
		if len(cfg.Resolvers) == 0 {
			// Use system resolver via DefaultResolver
			resolver := net.DefaultResolver
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
			ips, err = resolver.LookupHost(ctx, domain)
			cancel()
		} else {
			// Use custom resolver
			resolver := getResolver()
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
			ips, err = resolver.LookupHost(ctx, domain)
			cancel()
		}

		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				parsed := net.ParseIP(ip)
				if parsed == nil { continue }
				if parsed.To4() != nil {
					ipv4s = append(ipv4s, ip)
				} else {
					ipv6s = append(ipv6s, ip)
				}
			}
			elapsed := time.Since(start).Milliseconds()
			return ipv4s, ipv6s, elapsed, nil
		}
		lastErr = err
		if attempt < cfg.Retries {
			time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
		}
	}
	elapsed := time.Since(start).Milliseconds()
	return nil, nil, elapsed, lastErr
}

// ─── Domain Validation ────────────────────────────────────────────────────

func isValidDomain(domain string) bool {
	// Basic domain validation
	if len(domain) == 0 || len(domain) > 253 { return false }
	if strings.HasPrefix(domain, ".") || strings.HasPrefix(domain, "-") { return false }
	if strings.HasSuffix(domain, ".") || strings.HasSuffix(domain, "-") { return false }
	if strings.Count(domain, ".") == 0 { return false } // Must have at least one dot
	
	// Check for valid characters
	validRe := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	return validRe.MatchString(domain)
}

// ─── DNS Metrics Tracking ────────────────────────────────────────────────

type DNSMetrics struct {
	mu              sync.Mutex
	TotalQueries    int64
	SuccessQueries  int64
	FailedQueries   int64
	AverageTime     int64
	FastestTime     int64
	SlowestTime     int64
	TotalTime       int64
}

var dnsMetrics = &DNSMetrics{
	FastestTime: 9999999,
}

// ─── Resolver Factory ─────────────────────────────────────────────────────────

func makeResolver(resolverAddr string) *net.Resolver {
	// Use system resolver if no custom resolver specified
	if resolverAddr == "" || resolverAddr == "system" {
		// Return the default system resolver - respects /etc/resolv.conf and platform DNS settings
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			proto := cfg.Protocol
			if proto == "doh" { proto = "udp" }
			d := net.Dialer{Timeout: time.Duration(cfg.Timeout) * time.Second}
			return d.DialContext(ctx, proto, resolverAddr)
		},
	}
}

func getResolver() *net.Resolver {
	// If no custom resolvers specified, use system resolver
	if len(cfg.Resolvers) == 0 {
		return net.DefaultResolver
	}
	
	if cfg.RotateResolvers {
		idx := atomic.AddInt64(&resolverIdx, 1)
		r := cfg.Resolvers[idx%int64(len(cfg.Resolvers))]
		return makeResolver(r)
	}
	return makeResolver(cfg.Resolvers[rand.Intn(len(cfg.Resolvers))])
}

// ─── DNS Query with Retries ────────────────────────────────────────────────────

func resolveDomain(domain string) ([]string, []string, error) {
	var ipv4s, ipv6s []string
	var lastErr error

	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		var ips []string
		var err error
		
		if len(cfg.Resolvers) == 0 {
			// Use system resolver via DefaultResolver with context and timeout
			resolver := net.DefaultResolver
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
			ips, err = resolver.LookupHost(ctx, domain)
			cancel()
		} else {
			// Use custom resolver
			resolver := getResolver()
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
			ips, err = resolver.LookupHost(ctx, domain)
			cancel()
		}

		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				parsed := net.ParseIP(ip)
				if parsed == nil { continue }
				if parsed.To4() != nil {
					ipv4s = append(ipv4s, ip)
				} else {
					ipv6s = append(ipv6s, ip)
				}
			}
			return ipv4s, ipv6s, nil
		}
		lastErr = err
		if attempt < cfg.Retries {
			time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
		}
	}
	return nil, nil, lastErr
}

// ─── MX Lookup ────────────────────────────────────────────────────────────────

func lookupMX(domain string) []string {
	var mxRecords []*net.MX
	var err error
	
	var resolver *net.Resolver
	if len(cfg.Resolvers) == 0 {
		resolver = net.DefaultResolver
	} else {
		resolver = getResolver()
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	mxRecords, err = resolver.LookupMX(ctx, domain)
	cancel()
	
	if err != nil { return nil }
	var out []string
	for _, mx := range mxRecords {
		out = append(out, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
	}
	return out
}

// ─── NS Lookup ────────────────────────────────────────────────────────────────

func lookupNS(domain string) []string {
	var nsRecords []*net.NS
	var err error
	
	var resolver *net.Resolver
	if len(cfg.Resolvers) == 0 {
		resolver = net.DefaultResolver
	} else {
		resolver = getResolver()
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	nsRecords, err = resolver.LookupNS(ctx, domain)
	cancel()
	
	if err != nil { return nil }
	var out []string
	for _, ns := range nsRecords { out = append(out, ns.Host) }
	return out
}

// ─── TXT Lookup ───────────────────────────────────────────────────────────────

func lookupTXT(domain string) []string {
	var records []string
	var err error
	
	var resolver *net.Resolver
	if len(cfg.Resolvers) == 0 {
		resolver = net.DefaultResolver
	} else {
		resolver = getResolver()
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	records, err = resolver.LookupTXT(ctx, domain)
	cancel()
	
	if err != nil { return nil }
	return records
}

// ─── CNAME Lookup ─────────────────────────────────────────────────────────────

func lookupCNAME(domain string) string {
	var cname string
	var err error
	
	var resolver *net.Resolver
	if len(cfg.Resolvers) == 0 {
		resolver = net.DefaultResolver
	} else {
		resolver = getResolver()
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	cname, err = resolver.LookupCNAME(ctx, domain)
	cancel()
	
	if err != nil { return "" }
	return cname
}

// ─── Reverse DNS ──────────────────────────────────────────────────────────────

func reverseDNS(ip string) []string {
	var names []string
	var err error
	
	var resolver *net.Resolver
	if len(cfg.Resolvers) == 0 {
		resolver = net.DefaultResolver
	} else {
		resolver = getResolver()
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	names, err = resolver.LookupAddr(ctx, ip)
	cancel()
	
	if err != nil { return nil }
	return names
}

// ─── SOA Lookup ────────────────────────────────────────────────────────────────

func lookupSOA(domain string) []string {
	resolver := getResolver()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	defer cancel()
	// Note: Go's net package doesn't support direct SOA lookup via standard API
	// This would require using a DNS library like "github.com/miekg/dns"
	// For now, return empty to maintain compatibility
	_ = resolver // Use resolver to avoid linter warning
	_ = ctx
	return nil
}

// ─── SRV Lookup ────────────────────────────────────────────────────────────────

func lookupSRV(service, proto, name string) []string {
	_, addrs, err := net.LookupSRV(service, proto, name)
	if err != nil { return nil }
	var results []string
	for _, addr := range addrs {
		results = append(results, fmt.Sprintf("%s:%d", addr.Target, addr.Port))
	}
	return results
}

// ─── CAA Lookup ────────────────────────────────────────────────────────────────

func lookupCAA(domain string) []string {
	resolver := getResolver()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	defer cancel()
	// Note: Go's net package doesn't support direct CAA lookup via standard API
	// This would require using a DNS library like "github.com/miekg/dns"
	// For now, return empty to maintain compatibility
	_ = resolver // Use resolver to avoid linter warning
	_ = ctx
	return nil
}

// ─── CDN/Cloud Detection ──────────────────────────────────────────────────────

func detectCDN(ip string) string {
	for cdn, prefixes := range cdnRanges {
		for _, prefix := range prefixes {
			if strings.HasPrefix(ip, prefix) { return cdn }
		}
	}
	return ""
}

func detectCloud(ip string) string {
	for cloud, prefixes := range cloudRanges {
		for _, prefix := range prefixes {
			if strings.HasPrefix(ip, prefix) { return cloud }
		}
	}
	return ""
}

// ─── GeoIP Lookup (via ipinfo.io — free tier) ─────────────────────────────────

type IPInfoResponse struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
	Loc      string `json:"loc"`
}

var ipInfoCache sync.Map
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	},
}

func getIPInfo(ip string) *IPInfoResponse {
	if v, ok := ipInfoCache.Load(ip); ok { return v.(*IPInfoResponse) }
	resp, err := httpClient.Get("https://ipinfo.io/" + ip + "/json")
	if err != nil { return nil }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info IPInfoResponse
	if json.Unmarshal(body, &info) == nil {
		ipInfoCache.Store(ip, &info)
		return &info
	}
	return nil
}

// ─── TLS Probe ────────────────────────────────────────────────────────────────

func probeTLS(domain string) bool {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Duration(cfg.HTTPTimeout) * time.Second},
		"tcp", domain+":443",
		&tls.Config{ServerName: domain},
	)
	if err != nil { return false }
	conn.Close()
	return true
}

// ─── HTTP Probe ───────────────────────────────────────────────────────────────

type HTTPResult struct {
	Status int
	Title  string
	Tech   string
}

func probeHTTP(domain, scheme string) *HTTPResult {
	client := &http.Client{
		Timeout: time.Duration(cfg.HTTPTimeout) * time.Second,
	}
	if !cfg.FollowRedirs {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	req, err := http.NewRequest("GET", scheme+"://"+domain, nil)
	if err != nil { return nil }
	req.Header.Set("User-Agent", cfg.UserAgent)
	for _, h := range cfg.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 { req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])) }
	}
	resp, err := client.Do(req)
	if err != nil { return nil }
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*10))
	result := &HTTPResult{Status: resp.StatusCode}
	titleRe := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	if m := titleRe.FindSubmatch(body); len(m) > 1 {
		result.Title = strings.TrimSpace(string(m[1]))
		if len(result.Title) > 60 { result.Title = result.Title[:60] + "..." }
	}
	// Basic tech detection
	server := resp.Header.Get("Server")
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if server != "" { result.Tech = server }
	if xPoweredBy != "" {
		if result.Tech != "" { result.Tech += ", " + xPoweredBy } else { result.Tech = xPoweredBy }
	}
	return result
}

// ─── Port Scan ────────────────────────────────────────────────────────────────

var commonPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017}

func scanPorts(ip string, ports []int) []int {
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), time.Duration(cfg.Timeout)*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

// ─── Wildcard Detection ───────────────────────────────────────────────────────

func isWildcard(domain string) bool {
	randomSub := fmt.Sprintf("%x.%s", rand.Int63(), domain)
	ipv4s, _, err := resolveDomain(randomSub)
	return err == nil && len(ipv4s) > 0
}

// ─── Takeover Detection ───────────────────────────────────────────────────────

var takeoverSignatures = map[string]string{
	"GitHub Pages":         "There isn't a GitHub Pages site here",
	"Heroku":               "No such app",
	"Shopify":              "Sorry, this shop is currently unavailable",
	"Fastly":               "Fastly error: unknown domain",
	"WPEngine":             "The site you were looking for couldn't be found",
	"Amazon S3":            "NoSuchBucket",
	"Amazon CloudFront":    "Bad request",
	"Pantheon":             "404 error unknown site",
	"Zendesk":              "Help Center Closed",
	"Tumblr":               "Whatever you were looking for doesn't live here anymore",
	"Unbounce":             "The requested URL was not found on this server",
	"Ghost":                "The thing you were looking for is no longer here",
	"Webflow":              "The page you are looking for doesn't exist",
	"Surge.sh":             "project not found",
	"Bitbucket":            "Repository not found",
	"Launchrock":           "It looks like you may have taken a wrong turn somewhere",
}

func checkTakeover(domain string) string {
	resp, err := httpClient.Get("http://" + domain)
	if err != nil { return "" }
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(body)
	for service, sig := range takeoverSignatures {
		if strings.Contains(bodyStr, sig) { return service }
	}
	return ""
}

// ─── IP Detection ─────────────────────────────────────────────────────────────

func isIP(s string) bool {
	s = strings.TrimSpace(s)
	parsed := net.ParseIP(s)
	return parsed != nil
}

// ─── Private IP Detection ─────────────────────────────────────────────────────

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil { return false }
	privateRanges := []string{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","::1/128","fc00::/7","169.254.0.0/16"}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(parsed) { return true }
	}
	return false
}

// ─── CIDR Filter ──────────────────────────────────────────────────────────────

func ipInCIDR(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil { return false }
	return network.Contains(net.ParseIP(ip))
}

// ─── Color Helpers ────────────────────────────────────────────────────────────

func c(color, s string) string {
	if cfg.NoColor { return s }
	return color + s + reset
}

// ─── Output Helpers ───────────────────────────────────────────────────────────

func writeOutput(line string) {
	if outputFile != nil {
		fmt.Fprintln(outputFile, stripANSI(line))
	}
}

var ansiRe = regexp.MustCompile(`\033\[[0-9;]*m`)
func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// ─── Process IP (Reverse DNS Lookup) ──────────────────────────────────────────

func processIP(ip string) *Result {
	ip = strings.TrimSpace(ip)
	if ip == "" || !isIP(ip) { return nil }

	// Dedup
	if cfg.Deduplicate {
		if _, loaded := seenIPs.LoadOrStore(ip, true); loaded { return nil }
	}

	if cfg.Delay > 0 {
		time.Sleep(time.Duration(cfg.Delay) * time.Millisecond)
	}

	atomic.AddInt64(&stats.Total, 1)

	result := &Result{
		Domain:    ip,  // Store IP as "domain" field for compatibility
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IPs:       []string{ip},
	}

	// Reverse DNS lookup with timing
	var domains []string
	var dnsTime int64
	
	if cfg.ShowDNSTime || cfg.DNSMetrics {
		start := time.Now()
		domains = reverseDNS(ip)
		dnsTime = int64(time.Since(start).Milliseconds())
		result.DNSTime = dnsTime
		
		// Track DNS metrics
		dnsMetrics.mu.Lock()
		dnsMetrics.TotalQueries++
		dnsMetrics.TotalTime += dnsTime
		if dnsTime < dnsMetrics.FastestTime { dnsMetrics.FastestTime = dnsTime }
		if dnsTime > dnsMetrics.SlowestTime { dnsMetrics.SlowestTime = dnsTime }
		dnsMetrics.mu.Unlock()
	} else {
		domains = reverseDNS(ip)
	}

	if len(domains) == 0 {
		atomic.AddInt64(&stats.Failed, 1)
		dnsMetrics.mu.Lock()
		dnsMetrics.FailedQueries++
		dnsMetrics.mu.Unlock()
		return nil
	}
	atomic.AddInt64(&stats.Resolved, 1)
	
	dnsMetrics.mu.Lock()
	dnsMetrics.SuccessQueries++
	dnsMetrics.mu.Unlock()

	// Store reverse DNS results
	result.PTR = domains
	result.Domain = domains[0]  // Use first domain as primary

	// Private/Public filter
	if cfg.ExcludePrivate && isPrivateIP(ip) { return nil }
	if cfg.ExcludePublic && !isPrivateIP(ip) { return nil }

	// CIDR filter
	if cfg.FilterCIDR != "" && !ipInCIDR(ip, cfg.FilterCIDR) { return nil }
	if cfg.ExcludeCIDR != "" && ipInCIDR(ip, cfg.ExcludeCIDR) { return nil }

	// GeoIP/ASN enrichment
	if cfg.GeoIP || cfg.ASNLookup || cfg.ShowOrg || cfg.ShowISP || cfg.ShowCity || cfg.ShowCountry {
		info := getIPInfo(ip)
		if info != nil {
			result.Country = info.Country
			result.City = info.City
			result.Org = info.Org
			result.ASN = info.Org
		}
	}

	// CDN/Cloud detection
	if cfg.CDNCheck { result.CDN = detectCDN(ip) }
	if cfg.CloudCheck { result.Cloud = detectCloud(ip) }
	if cfg.ExcludeCDN && result.CDN != "" { return nil }

	// IP Reputation scoring
	if cfg.RepCheck {
		result.Reputation = scoreReputation(ip)
	}

	// Service detection on common ports
	if cfg.ServiceDetect {
		portList := []int{21, 22, 25, 80, 443, 3306, 5432, 8080, 8443}
		if len(cfg.Ports) > 0 { portList = cfg.Ports }
		for _, port := range portList {
			if service := detectService(ip, port); service != "" {
				result.Services = append(result.Services, service)
			}
		}
	}

	// HTTP probe
	if cfg.HTTPProbe || cfg.HTTPTitle || cfg.HTTPStatus {
		hr := probeHTTP(result.Domain, "http")
		if hr != nil {
			result.Status = hr.Status
			result.Title = hr.Title
		}
	}
	if cfg.HTTPSProbe {
		hr := probeHTTP(result.Domain, "https")
		if hr != nil && result.Status == 0 {
			result.Status = hr.Status
			if result.Title == "" { result.Title = hr.Title }
		}
	}

	// TLS probe on first domain
	if cfg.TLSProbe && len(domains) > 0 {
		result.TLSValid = probeTLS(domains[0])
	}

	return result
}

// ─── Process Domain ───────────────────────────────────────────────────────────

func processDomain(domain string) *Result {
	domain = strings.TrimSpace(domain)
	if domain == "" { return nil }

	// Domain validation
	if cfg.ValidateDomains && !isValidDomain(domain) {
		if !cfg.Silent { fmt.Fprintf(os.Stderr, "%s[WARN]%s Invalid domain: %s\n", yellow, reset, domain) }
		return nil
	}

	// Dedup
	if cfg.Deduplicate {
		if _, loaded := seenDomains.LoadOrStore(domain, true); loaded { return nil }
	}

	if cfg.Delay > 0 {
		time.Sleep(time.Duration(cfg.Delay) * time.Millisecond)
	}

	atomic.AddInt64(&stats.Total, 1)

	result := &Result{
		Domain:    domain,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Core DNS resolution with timing
	var ipv4s, ipv6s []string
	var dnsTime int64
	var err error
	
	if cfg.ShowDNSTime || cfg.DNSMetrics {
		ipv4s, ipv6s, dnsTime, err = resolveDomainTimed(domain)
		result.DNSTime = dnsTime
		
		// Track DNS metrics
		dnsMetrics.mu.Lock()
		dnsMetrics.TotalQueries++
		dnsMetrics.TotalTime += dnsTime
		if dnsTime < dnsMetrics.FastestTime { dnsMetrics.FastestTime = dnsTime }
		if dnsTime > dnsMetrics.SlowestTime { dnsMetrics.SlowestTime = dnsTime }
		dnsMetrics.mu.Unlock()
	} else {
		ipv4s, ipv6s, err = resolveDomain(domain)
	}
	
	if err != nil || (len(ipv4s) == 0 && len(ipv6s) == 0) {
		atomic.AddInt64(&stats.Failed, 1)
		dnsMetrics.mu.Lock()
		dnsMetrics.FailedQueries++
		dnsMetrics.mu.Unlock()
		return nil
	}
	atomic.AddInt64(&stats.Resolved, 1)
	
	dnsMetrics.mu.Lock()
	dnsMetrics.SuccessQueries++
	dnsMetrics.mu.Unlock()

	result.IPv4 = ipv4s
	result.IPv6 = ipv6s
	result.IPs = append(ipv4s, ipv6s...)

	// Apply IPv4/IPv6 filter
	if cfg.IPv4Only { result.IPs = ipv4s }
	if cfg.IPv6Only { result.IPs = ipv6s }
	if len(result.IPs) == 0 { return nil }

	primaryIP := result.IPs[0]

	// Private/Public filter
	if cfg.ExcludePrivate && isPrivateIP(primaryIP) { return nil }
	if cfg.ExcludePublic && !isPrivateIP(primaryIP) { return nil }

	// CIDR filter
	if cfg.FilterCIDR != "" && !ipInCIDR(primaryIP, cfg.FilterCIDR) { return nil }
	if cfg.ExcludeCIDR != "" && ipInCIDR(primaryIP, cfg.ExcludeCIDR) { return nil }

	// Extra record types
	if cfg.AllRecords || cfg.LookupMX { result.MX = lookupMX(domain) }
	if cfg.AllRecords || cfg.LookupNS { result.NS = lookupNS(domain) }
	if cfg.AllRecords || cfg.LookupTXT { result.TXT = lookupTXT(domain) }
	if cfg.AllRecords || cfg.LookupCNAME { result.CNAME = lookupCNAME(domain) }
	if cfg.AllRecords || cfg.LookupSOA { result.SOA = lookupSOA(domain) }
	if cfg.AllRecords || cfg.LookupSRV { result.SRV = lookupSRV("", "", domain) }
	if cfg.AllRecords || cfg.LookupCAA { result.CAA = lookupCAA(domain) }
	if cfg.ReverseDNS { result.PTR = reverseDNS(result.IPs[0]) }

	// CDN/Cloud detection
	if cfg.CDNCheck { result.CDN = detectCDN(primaryIP) }
	if cfg.CloudCheck { result.Cloud = detectCloud(primaryIP) }
	if cfg.ExcludeCDN && result.CDN != "" { return nil }

	// Wildcard detection
	if cfg.Wildcard {
		parentDomain := strings.Join(strings.Split(domain, ".")[1:], ".")
		result.Wildcard = isWildcard(parentDomain)
		if cfg.ExcludeWildcard && result.Wildcard { return nil }
		if cfg.OnlyWildcard && !result.Wildcard { return nil }
	}

	// GeoIP/ASN enrichment
	if cfg.GeoIP || cfg.ASNLookup || cfg.ShowOrg || cfg.ShowISP || cfg.ShowCity || cfg.ShowCountry {
		info := getIPInfo(primaryIP)
		if info != nil {
			result.Country = info.Country
			result.City = info.City
			result.Org = info.Org
			result.ASN = info.Org // Org field contains ASN info from ipinfo
		}
	}

	// TLS probe
	if cfg.TLSProbe { result.TLSValid = probeTLS(domain) }

	// HTTP probe
	if cfg.HTTPProbe || cfg.HTTPTitle || cfg.HTTPStatus {
		hr := probeHTTP(domain, "http")
		if hr != nil {
			result.Status = hr.Status
			result.Title = hr.Title
		}
	}
	if cfg.HTTPSProbe {
		hr := probeHTTP(domain, "https")
		if hr != nil && result.Status == 0 {
			result.Status = hr.Status
			if result.Title == "" { result.Title = hr.Title }
		}
	}

	// Takeover detection
	if cfg.TakeOver {
		to := checkTakeover(domain)
		if to != "" { result.Title = "[TAKEOVER:" + to + "] " + result.Title }
	}

	// ─── NEW FEATURES ─────────────────────────────────────────────────────
	
	// Extract emails from DNS records
	if cfg.ExtractEmails && (len(result.MX) > 0 || len(result.TXT) > 0) {
		result.Emails = extractEmails(result.MX, result.TXT)
	}

	// IP Reputation scoring
	if cfg.RepCheck {
		result.Reputation = scoreReputation(primaryIP)
	}

	// Service detection on common ports
	if cfg.ServiceDetect {
		portList := []int{21, 22, 25, 80, 443, 3306, 5432, 8080, 8443}
		if len(cfg.Ports) > 0 { portList = cfg.Ports }
		for _, port := range portList {
			if service := detectService(primaryIP, port); service != "" {
				result.Services = append(result.Services, service)
			}
		}
	}

	return result
}

// ─── Format & Print Result ────────────────────────────────────────────────────

func printResult(r *Result) {
	if r == nil { return }

	primaryIP := ""
	if len(r.IPs) > 0 { primaryIP = r.IPs[0] }

	// Update stats immediately (before any early returns)
	stats.mu.Lock()
	if primaryIP != "" { stats.IPSet[primaryIP] = true }
	if r.Country != "" { stats.CountrySet[r.Country]++ }
	if r.CDN != "" { stats.CDNSet[r.CDN]++ }
	if r.Cloud != "" { stats.CloudSet[r.Cloud]++ }
	stats.mu.Unlock()

	switch cfg.OutputFormat {
	case "json":
		// JSON printed at end in summary
		return
	case "csv":
		if csvWriter != nil {
			csvWriter.Write([]string{
				r.Domain,
				strconv.Itoa(len(r.IPs)),
				strings.Join(r.IPv4, "|"),
				strings.Join(r.IPv6, "|"),
				strings.Join(r.MX, "|"),
				strings.Join(r.NS, "|"),
				strings.Join(r.TXT, "|"),
				r.CNAME,
				strings.Join(r.SOA, "|"),
				strings.Join(r.SRV, "|"),
				strings.Join(r.CAA, "|"),
				strings.Join(r.PTR, "|"),
				r.Country,
				r.City,
				r.Org,
				r.ISP,
				r.ASN,
				r.CDN,
				r.Cloud,
				strconv.Itoa(r.Status),
				r.Title,
				strconv.FormatBool(r.TLSValid),
				strconv.FormatBool(r.Wildcard),
				strconv.Itoa(r.Reputation),
				strconv.FormatInt(r.DNSTime, 10),
				strings.Join(r.Emails, "|"),
				strings.Join(r.Services, "|"),
				r.Timestamp,
			})
			csvWriter.Flush()
		}
		return
	case "txt":
		// TXT format: IP only (one per line)
		for _, ip := range r.IPs {
			if !cfg.Silent { fmt.Println(ip) }
			writeOutput(ip)
		}
		return
	case "nmap":
		line := primaryIP
		if !cfg.Silent { fmt.Println(line) }
		writeOutput(line)
		return
	case "masscan":
		for _, ip := range r.IPs {
			line := ip
			if !cfg.Silent { fmt.Println(line) }
			writeOutput(line)
		}
		return
	}

	if cfg.Silent {
		if cfg.ReverseMode && len(r.PTR) > 0 {
			// In reverse mode, output resolved domains
			for _, domain := range r.PTR { fmt.Println(domain) }
		} else if !cfg.ReverseMode && len(r.IPs) > 0 {
			// In forward mode, output IPs
			for _, ip := range r.IPs { fmt.Println(ip) }
		}
		return
	}

	// Pretty terminal output
	var parts []string
	
	if cfg.ReverseMode {
		// Reverse mode: IP → Domains
		parts = append(parts, c(blue, "[DNS]")+" "+c(white, fmt.Sprintf("%-40s", r.IPs[0])))
		if len(r.PTR) > 0 {
			for i, domain := range r.PTR {
				if i == 0 {
					parts = append(parts, c(grey, "→ "+domain))
				} else {
					parts = append(parts, c(dim+grey, "  "+domain))
				}
			}
		} else {
			parts = append(parts, c(dim+grey, "[No PTR record]"))
		}
	} else {
		// Forward mode: Domain → IPs
		parts = append(parts, c(blue, "[IP]")+" "+c(white, fmt.Sprintf("%-40s", r.Domain)))
		parts = append(parts, c(grey, "["+primaryIP+"]"))
		
		if len(r.IPs) > 1 {
			parts = append(parts, c(dim+grey, "(+"+strconv.Itoa(len(r.IPs)-1)+")"))
		}
	}
	
	// Show DNS timing if available
	if r.DNSTime > 0 && cfg.ShowDNSTime {
		parts = append(parts, c(lightGreen, fmt.Sprintf("[%dms]", r.DNSTime)))
	}
	
	// Show reputation score
	if cfg.RepCheck && r.Reputation > 0 {
		repColor := green
		if r.Reputation < 50 { repColor = red } else if r.Reputation < 75 { repColor = yellow }
		parts = append(parts, c(repColor, fmt.Sprintf("[Rep:%d]", r.Reputation)))
	}
	
	// Show emails
	if cfg.ExtractEmails && len(r.Emails) > 0 {
		parts = append(parts, c(cyan, fmt.Sprintf("[%d emails]", len(r.Emails))))
	}
	
	// Show services
	if cfg.ServiceDetect && len(r.Services) > 0 {
		parts = append(parts, c(orange, fmt.Sprintf("[%d services]", len(r.Services))))
	}
	
	// Only show extras if explicitly requested via flags
	if cfg.ShowCountry && r.Country != "" {
		parts = append(parts, c(yellow, "["+r.Country+"]"))
	}
	if cfg.ShowCity && r.City != "" {
		parts = append(parts, c(yellow, r.City))
	}
	if cfg.ShowOrg && r.Org != "" {
		org := r.Org; if len(org) > 20 { org = org[:20] }
		parts = append(parts, c(purple, "["+org+"]"))
	}
	if cfg.CDNCheck && r.CDN != "" {
		parts = append(parts, c(orange, "[CDN:"+r.CDN+"]"))
	}
	if cfg.CloudCheck && r.Cloud != "" {
		parts = append(parts, c(lightBlue, "["+r.Cloud+"]"))
	}
	if r.Status != 0 && cfg.HTTPProbe {
		sc := strconv.Itoa(r.Status)
		col := green; if r.Status >= 400 { col = red } else if r.Status >= 300 { col = yellow }
		parts = append(parts, c(col, "["+sc+"]"))
	}
	if r.Title != "" && cfg.HTTPTitle {
		parts = append(parts, c(dim+white, "["+r.Title+"]"))
	}
	if r.TLSValid && cfg.TLSProbe {
		parts = append(parts, c(green, "[TLS✓]"))
	}
	if r.Wildcard && cfg.Wildcard {
		parts = append(parts, c(magenta, "[WILDCARD]"))
	}
	if r.CNAME != "" && (cfg.LookupCNAME || cfg.AllRecords) && cfg.Verbose {
		parts = append(parts, c(lightGreen, "[CNAME:"+strings.TrimRight(r.CNAME, ".")+"]"))
	}
	if len(r.MX) > 0 && (cfg.LookupMX || cfg.AllRecords) && cfg.Verbose {
		parts = append(parts, c(cyan, "[MX:"+strconv.Itoa(len(r.MX))+"]"))
	}
	if len(r.PTR) > 0 && cfg.Verbose {
		parts = append(parts, c(grey, "[PTR:"+r.PTR[0]+"]"))
	}

	line := strings.Join(parts, " ")
	fmt.Println(line)
	writeOutput(line)

	// Verbose extra records
	if cfg.Verbose {
		if len(r.IPv6) > 0 {
			for _, ip := range r.IPv6 {
				fmt.Printf("  %s %s %s\n", c(cyan, "[AAAA]"), c(white, r.Domain), c(grey, "["+ip+"]"))
			}
		}
		if len(r.NS) > 0 { fmt.Printf("  %s %s\n", c(yellow, "[NS]"), strings.Join(r.NS, " | ")) }
		if len(r.TXT) > 0 {
			for _, t := range r.TXT {
				if len(t) > 100 { t = t[:100] + "..." }
				fmt.Printf("  %s %s\n", c(grey, "[TXT]"), t)
			}
		}
		
		// Show emails if found
		if len(r.Emails) > 0 {
			for _, email := range r.Emails {
				fmt.Printf("  %s %s\n", c(cyan, "[EMAIL]"), email)
			}
		}
		
		// Show services if found
		if len(r.Services) > 0 {
			for _, service := range r.Services {
				fmt.Printf("  %s %s\n", c(orange, "[SERVICE]"), service)
			}
		}
	}

	// Stats already updated at function start
}

// ─── Progress Bar (Sticky at Bottom) ──────────────────────────────────────────

func startProgress(total int) {
	if !cfg.Progress || total == 0 { return }
	go func() {
		lastLine := ""
		for {
			resolved := atomic.LoadInt64(&stats.Resolved)
			tot := atomic.LoadInt64(&stats.Total)
			pct := 0
			if total > 0 { pct = int(tot) * 100 / total }
			elapsed := time.Since(stats.StartTime).Seconds()
			rate := 0.0
			if elapsed > 0 { rate = float64(tot) / elapsed }
			bar := strings.Repeat("█", pct/5) + strings.Repeat("░", 20-pct/5)
			
			// Format progress line with fixed width to avoid wrapping
			progLine := fmt.Sprintf("%s[%s]%s %3d%% | %d/%d | Found: %s%d%s | %.0f/s",
				grey, bar, reset, pct, tot, total, green, resolved, reset, rate)
			
			// Only print if changed (reduce spam)
			if progLine != lastLine {
				// Use escape codes to clear line and move cursor to start, then print
				fmt.Fprintf(os.Stderr, "\r\033[2K%s", progLine)
				lastLine = progLine
			}
			
			if int(tot) >= total { break }
			time.Sleep(100 * time.Millisecond)
		}
		// Final newline to move past progress bar
		fmt.Fprintln(os.Stderr)
	}()
}

// ─── Summary ──────────────────────────────────────────────────────────────────

func printSummary() {
	if !cfg.Summary && !cfg.Stats { return }
	elapsed := time.Since(stats.StartTime)
	total := atomic.LoadInt64(&stats.Total)
	resolved := atomic.LoadInt64(&stats.Resolved)
	failed := atomic.LoadInt64(&stats.Failed)

	fmt.Println()
	fmt.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", bold, grey, reset)
	fmt.Printf("  %s%-20s%s %s%d%s\n", grey, "Total Processed:", reset, white, total, reset)
	fmt.Printf("  %s%-20s%s %s%d%s\n", grey, "Resolved:", reset, green, resolved, reset)
	fmt.Printf("  %s%-20s%s %s%d%s\n", grey, "Failed:", reset, red, failed, reset)
	fmt.Printf("  %s%-20s%s %s%d%s\n", grey, "Unique IPs:", reset, cyan, len(stats.IPSet), reset)
	fmt.Printf("  %s%-20s%s %s%.2fs%s\n", grey, "Elapsed:", reset, yellow, elapsed.Seconds(), reset)
	if elapsed.Seconds() > 0 {
		fmt.Printf("  %s%-20s%s %s%.0f/s%s\n", grey, "Rate:", reset, orange, float64(total)/elapsed.Seconds(), reset)
	}

	// DNS Metrics
	if cfg.DNSMetrics && dnsMetrics.TotalQueries > 0 {
		fmt.Printf("\n  %s%sDNS Query Metrics:%s\n", bold, grey, reset)
		fmt.Printf("    %s%-20s%s %s%d%s\n", grey, "Queries:", reset, white, dnsMetrics.TotalQueries, reset)
		fmt.Printf("    %s%-20s%s %s%d%s\n", grey, "Successful:", reset, green, dnsMetrics.SuccessQueries, reset)
		fmt.Printf("    %s%-20s%s %s%d%s\n", grey, "Failed:", reset, red, dnsMetrics.FailedQueries, reset)
		if dnsMetrics.SuccessQueries > 0 {
			avgTime := dnsMetrics.TotalTime / dnsMetrics.SuccessQueries
			fmt.Printf("    %s%-20s%s %s%dms%s\n", grey, "Avg Query Time:", reset, cyan, avgTime, reset)
			fmt.Printf("    %s%-20s%s %s%dms%s\n", grey, "Fastest Query:", reset, green, dnsMetrics.FastestTime, reset)
			fmt.Printf("    %s%-20s%s %s%dms%s\n", grey, "Slowest Query:", reset, yellow, dnsMetrics.SlowestTime, reset)
		}
	}

	if len(stats.CountrySet) > 0 {
		fmt.Printf("\n  %s%sCountry Distribution:%s\n", bold, grey, reset)
		type kv struct { K string; V int }
		var sorted []kv
		for k, v := range stats.CountrySet { sorted = append(sorted, kv{k, v}) }
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].V > sorted[j].V })
		limit := 5; if len(sorted) < limit { limit = len(sorted) }
		for _, kv := range sorted[:limit] {
			fmt.Printf("    %s%-8s%s %d\n", yellow, kv.K, reset, kv.V)
		}
	}

	if len(stats.CDNSet) > 0 {
		fmt.Printf("\n  %s%sCDN Distribution:%s\n", bold, grey, reset)
		for k, v := range stats.CDNSet {
			fmt.Printf("    %s%-20s%s %d\n", orange, k, reset, v)
		}
	}

	fmt.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", bold, grey, reset)
}

// ─── Auto Update ──────────────────────────────────────────────────────────────

func doUpdate() {
	fmt.Printf("%s[INF]%s Checking for updates from %s%s%s...\n", cyan, reset, grey, repo, reset)

	resp, err := httpClient.Get("https://api.github.com/repos/mohidqx/sub2ip/releases/latest")
	if err != nil {
		fmt.Printf("%s[ERR]%s Failed to check latest version: %v\n", red, reset, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var release struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
	}
	if json.Unmarshal(body, &release) != nil || release.TagName == "" {
		fmt.Printf("%s[ERR]%s Could not parse release info\n", red, reset)
		return
	}

	latestTag := strings.TrimPrefix(release.TagName, "v")
	fmt.Printf("%s[INF]%s Current: %s%s%s | Latest: %s%s%s\n",
		cyan, reset, grey, version, reset, green, latestTag, reset)

	if latestTag == version {
		fmt.Printf("%s[INF]%s Already up to date!\n", green, reset)
		return
	}

	fmt.Printf("%s[INF]%s New version available! Running: go install %s@latest\n", yellow, reset, repo)
	cmd := exec.Command("go", "install", repo+"@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("%s[ERR]%s Update failed: %v\n", red, reset, err)
		fmt.Printf("%s[INF]%s Manual: go install %s@latest\n", grey, reset, repo)
		return
	}
	fmt.Printf("%s[INF]%s Successfully updated to v%s!\n", green, reset, latestTag)
}

// ─── Load Domains from File ───────────────────────────────────────────────────

func loadFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// ─── Load Custom Resolvers ────────────────────────────────────────────────────

func loadResolvers() {
	if cfg.ResolverFile == "" { return }
	lines, err := loadFile(cfg.ResolverFile)
	if err != nil { return }
	cfg.Resolvers = nil
	for _, line := range lines {
		if !strings.Contains(line, ":") { line += ":53" }
		cfg.Resolvers = append(cfg.Resolvers, line)
	}
	fmt.Printf("%s[INF]%s Loaded %d resolvers from %s\n", cyan, reset, len(cfg.Resolvers), cfg.ResolverFile)
}

// ─── Setup Output ─────────────────────────────────────────────────────────────

func setupOutput() {
	if cfg.OutputFile == "" { return }
	flag := os.O_CREATE | os.O_WRONLY
	if cfg.AppendMode { flag |= os.O_APPEND } else { flag |= os.O_TRUNC }
	var err error
	outputFile, err = os.OpenFile(cfg.OutputFile, flag, 0644)
	if err != nil { fmt.Fprintf(os.Stderr, "%s[ERR]%s Cannot open output file: %v\n", red, reset, err); os.Exit(1) }

	if cfg.OutputFormat == "csv" {
		csvWriter = csv.NewWriter(outputFile)
		// Comprehensive CSV header with ALL DNS records and data
		csvWriter.Write([]string{
			"domain","ips_count","ipv4","ipv6","mx","ns","txt","cname","soa","srv","caa","ptr",
			"country","city","org","isp","asn","cdn","cloud",
			"http_status","http_title","tls_valid","wildcard",
			"reputation_score","dns_query_ms","emails","services","timestamp",
		})
		csvWriter.Flush()
	}
}

// ─── DNS Brute Force ──────────────────────────────────────────────────────────

func doBrute(base string, wordlist []string) []string {
	var found []string
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for _, word := range wordlist {
		sub := word + "." + base
		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()
			ips, _, err := resolveDomain(s)
			if err == nil && len(ips) > 0 {
				mu.Lock(); found = append(found, s); mu.Unlock()
				fmt.Printf("%s[BRUTE]%s %s %s[%s]%s\n", magenta, reset, s, grey, ips[0], reset)
			}
		}(sub)
	}
	wg.Wait()
	return found
}

// ─── Domain Permutation ───────────────────────────────────────────────────────

func permuteDomain(domain string, words []string) []string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 { return nil }
	base := strings.Join(parts[len(parts)-2:], ".")
	sub := strings.Join(parts[:len(parts)-2], ".")
	var perms []string
	for _, w := range words {
		perms = append(perms,
			w+"-"+sub+"."+base,
			sub+"-"+w+"."+base,
			w+sub+"."+base,
			sub+w+"."+base,
			w+"."+sub+"."+base,
		)
	}
	return perms
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	// Detect tool name from executable (ip2sub vs sub2ip)
	toolName = getToolName()
	
	// If running as ip2sub, automatically enable reverse mode
	if toolName == "ip2sub" {
		cfg.ReverseMode = true
	}
	
	parseFlags()

	if cfg.Update { doUpdate(); return }
	if cfg.Version {
		fmt.Printf("%s v%s (%s/%s)\n", toolName, version, runtime.GOOS, runtime.GOARCH)
		return
	}
	if cfg.Help { printBanner(); printHelp(); return }
	if !cfg.NoBanner { printBanner() }

	loadResolvers()
	setupOutput()
	defer func() {
		if outputFile != nil { outputFile.Close() }
	}()

	// ─── Collect domains ────────────────────────────────────────────────────
	var domains []string

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" { domains = append(domains, line) }
		}
	} else if cfg.InputFile != "" {
		var err error
		domains, err = loadFile(cfg.InputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[ERR]%s Cannot open file: %v\n", red, reset, err)
			os.Exit(1)
		}
	} else if cfg.Domain != "" {
		domains = []string{cfg.Domain}
	} else {
		printHelp()
		os.Exit(0)
	}

	if cfg.LineCount {
		mode := "domains"
		if cfg.ReverseMode { mode = "IPs" }
		fmt.Printf("%s[INF]%s Input: %s%d%s %s\n", cyan, reset, white, len(domains), reset, mode)
	}

	// ─── Permutation expansion ──────────────────────────────────────────────
	if cfg.Permute && len(cfg.PermuteWords) > 0 {
		if cfg.ReverseMode {
			fmt.Fprintf(os.Stderr, "%s[WARN]%s Permutation not supported in reverse mode\n", yellow, reset)
		} else {
			var extra []string
			for _, d := range domains {
				extra = append(extra, permuteDomain(d, cfg.PermuteWords)...)
			}
			domains = append(domains, extra...)
			fmt.Printf("%s[INF]%s After permutation: %d domains\n", cyan, reset, len(domains))
		}
	}

	// ─── DNS Brute Force ────────────────────────────────────────────────────
	if cfg.DNSBrute && cfg.Domain != "" {
		if cfg.ReverseMode {
			fmt.Fprintf(os.Stderr, "%s[WARN]%s DNS brute force not supported in reverse mode\n", yellow, reset)
		} else {
			wordlist := []string{"www","mail","ftp","admin","api","dev","stage","test","vpn","ns","ns1","ns2","smtp","pop","imap","webmail","blog","shop","app","cdn","static","assets","media","images","portal","login","secure","auth"}
			if cfg.WordlistFile != "" {
				if wl, err := loadFile(cfg.WordlistFile); err == nil { wordlist = wl }
			}
			doBrute(cfg.Domain, wordlist)
			return
		}
	}

	// ─── Start progress bar ─────────────────────────────────────────────────
	startProgress(len(domains))

	// ─── Worker pool ────────────────────────────────────────────────────────
	jobs := make(chan string, cfg.Concurrency*2)
	var wg sync.WaitGroup

	var allResults []Result
	var resMu sync.Mutex

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				var r *Result
				if cfg.ReverseMode {
					// IP-to-domain reverse lookup mode
					r = processIP(item)
				} else {
					// Domain-to-IP lookup mode (default)
					r = processDomain(item)
				}
				if r != nil {
					printResult(r)
					if cfg.OutputFormat == "json" || cfg.Summary {
						resMu.Lock()
						allResults = append(allResults, *r)
						resMu.Unlock()
					}
				}
			}
		}()
	}

	// Feed jobs with optional rate limiting
	var rateLimiter <-chan time.Time
	if cfg.RateLimit > 0 {
		rateLimiter = time.Tick(time.Second / time.Duration(cfg.RateLimit))
	}

	for _, d := range domains {
		if rateLimiter != nil { <-rateLimiter }
		jobs <- d
	}
	close(jobs)
	wg.Wait()

	// ─── JSON output ────────────────────────────────────────────────────────
	if cfg.OutputFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(allResults)
		if outputFile != nil {
			enc2 := json.NewEncoder(outputFile)
			enc2.SetIndent("", "  ")
			enc2.Encode(allResults)
		}
	}

	// ─── Sort output ────────────────────────────────────────────────────────
	if (cfg.SortOutput || cfg.ReverseSort) && len(allResults) > 0 {
		sort.Slice(allResults, func(i, j int) bool {
			if cfg.ReverseSort { return allResults[i].Domain > allResults[j].Domain }
			return allResults[i].Domain < allResults[j].Domain
		})
		for _, r := range allResults {
			if len(r.IPs) > 0 {
				fmt.Printf("%-40s %s\n", r.Domain, r.IPs[0])
			}
		}
	}

	// ─── Count ──────────────────────────────────────────────────────────────
	if cfg.Count {
		fmt.Printf("\n%s[INF]%s Resolved: %s%d%s unique hostnames\n",
			cyan, reset, green, atomic.LoadInt64(&stats.Resolved), reset)
	}

	// ─── Summary ────────────────────────────────────────────────────────────
	printSummary()

	// ─── Output file info ───────────────────────────────────────────────────
	if outputFile != nil && !cfg.Silent {
		absPath, _ := filepath.Abs(cfg.OutputFile)
		fmt.Printf("%s[INF]%s Results saved to: %s%s%s\n", cyan, reset, grey, absPath, reset)
	}
}