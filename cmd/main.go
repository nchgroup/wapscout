package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"wapscout/internal/output"
	"wapscout/internal/scanner"

	"github.com/spf13/cobra"
)

var version = "1.0.0"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── Shared flags ──────────────────────────────────────────────────────────────

var (
	flagFormat      string
	flagNoColor     bool
	flagShowMeta    bool
	flagTimeout     int
	flagConcurrency int
	flagProxy       string
	flagInsecure    bool
	flagUserAgent   string
	flagOutputFile  string
	flagHeaders     []string
	flagNoRedirect  bool
	flagSilent      bool
)

// ── Root command ──────────────────────────────────────────────────────────────

var rootCmd = &cobra.Command{
	Use:   "wapscout",
	Short: "WapScout — Technology Detection CLI",
	Long: `WapScout is a fast CLI tool for detecting web technologies.
It leverages the wappalyzergo library to fingerprint URLs and identify
frameworks, CMS, servers, analytics, and much more.

Examples:
  wapscout scan https://example.com
  wapscout scan -f json https://github.com
  wapscout batch -i urls.txt -f csv -o results.csv
  echo "https://cloudflare.com" | wapscout scan -
  wapscout scan https://wordpress.com --show-meta`,
	Version: version,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(batchCmd)
	rootCmd.AddCommand(versionCmd)

	// Global persistent flags
	for _, cmd := range []*cobra.Command{scanCmd, batchCmd} {
		cmd.Flags().StringVarP(&flagFormat, "format", "f", "pretty", "Output format: pretty, json, csv, plain")
		cmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
		cmd.Flags().BoolVar(&flagShowMeta, "show-meta", false, "Show additional metadata (headers, categories)")
		cmd.Flags().IntVarP(&flagTimeout, "timeout", "t", 15, "HTTP timeout in seconds")
		cmd.Flags().StringVarP(&flagProxy, "proxy", "p", "", "HTTP/SOCKS5 proxy URL (e.g. http://127.0.0.1:8080)")
		cmd.Flags().BoolVar(&flagInsecure, "insecure", false, "Skip TLS certificate verification")
		cmd.Flags().StringVarP(&flagUserAgent, "user-agent", "u", "", "Custom User-Agent string")
		cmd.Flags().StringVarP(&flagOutputFile, "output", "o", "", "Write output to file")
		cmd.Flags().StringArrayVarP(&flagHeaders, "header", "H", nil, "Custom headers (key:value), repeatable")
		cmd.Flags().BoolVar(&flagNoRedirect, "no-redirect", false, "Do not follow HTTP redirects")
		cmd.Flags().BoolVar(&flagSilent, "silent", false, "Suppress banner and informational output")
	}

	scanCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 1, "Concurrent requests (for multiple URLs)")
	batchCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 5, "Max concurrent requests")
	batchCmd.Flags().StringVarP(&flagInputFile, "input", "i", "", "Input file with URLs (one per line)")
}

// ── Build scanner options ─────────────────────────────────────────────────────

func buildScannerOptions() scanner.Options {
	opts := scanner.DefaultOptions()
	opts.Timeout = time.Duration(flagTimeout) * time.Second
	opts.InsecureSkip = flagInsecure
	opts.FollowRedirect = !flagNoRedirect
	opts.Concurrency = flagConcurrency

	if flagProxy != "" {
		opts.Proxy = flagProxy
	}
	if flagUserAgent != "" {
		opts.UserAgent = flagUserAgent
	}

	opts.Headers = make(map[string]string)
	for _, h := range flagHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			opts.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return opts
}

func buildPrinter() (*output.Printer, *os.File) {
	var outFile *os.File
	if flagOutputFile != "" {
		f, err := os.Create(flagOutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create output file: %v\n", err)
			os.Exit(1)
		}
		outFile = f
	}
	p := output.NewPrinter(output.Format(flagFormat), flagNoColor, flagShowMeta, outFile)
	return p, outFile
}

// ── scan command ──────────────────────────────────────────────────────────────

var scanCmd = &cobra.Command{
	Use:   "scan [url...] or - (stdin)",
	Short: "Scan one or more URLs for technologies",
	Long: `Scan one or more URLs and print detected technologies.

Use '-' as the URL argument to read URLs from stdin.

Examples:
  wapscout scan https://github.com
  wapscout scan https://github.com https://gitlab.com -f json
  echo "https://example.com" | wapscout scan -
  wapscout scan https://wordpress.com --show-meta -f json`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !flagSilent {
			output.PrintBanner()
		}

		opts := buildScannerOptions()
		sc, err := scanner.New(opts)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		printer, outFile := buildPrinter()
		if outFile != nil {
			defer outFile.Close()
		}

		// Collect URLs
		var urls []string
		for _, arg := range args {
			if arg == "-" {
				stdinURLs, err := readLines(os.Stdin)
				if err != nil {
					return err
				}
				urls = append(urls, stdinURLs...)
			} else {
				urls = append(urls, arg)
			}
		}

		if len(urls) == 0 {
			return fmt.Errorf("no URLs provided")
		}

		if len(urls) == 1 {
			result := sc.Scan(urls[0])
			if flagFormat == "json" || flagFormat == "csv" {
				if flagFormat == "csv" {
					printer.PrintCSVHeaderPublic()
				}
				printer.PrintResult(result)
			} else {
				printer.PrintResult(result)
			}
			return nil
		}

		// Multiple URLs — batch scan
		opts.Concurrency = max(flagConcurrency, 1)
		results := sc.ScanBatch(urls, func(done, total int) {
			if !flagSilent {
				fmt.Fprintf(os.Stderr, "\r  Scanning... %d/%d", done, total)
			}
		})
		if !flagSilent && len(urls) > 1 {
			fmt.Fprintln(os.Stderr)
		}

		printer.PrintResults(results)
		return nil
	},
}

// ── batch command ─────────────────────────────────────────────────────────────

var flagInputFile string

var batchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Batch-scan URLs from a file or stdin",
	Long: `Read URLs from a file (one per line) or stdin and scan them concurrently.

Examples:
  wapscout batch -i urls.txt
  wapscout batch -i urls.txt -f json -o results.json -c 10
  cat urls.txt | wapscout batch -f csv -o results.csv`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !flagSilent {
			output.PrintBanner()
		}

		var urls []string
		var err error

		if flagInputFile != "" {
			f, err := os.Open(flagInputFile)
			if err != nil {
				return fmt.Errorf("cannot open input file: %w", err)
			}
			defer f.Close()
			urls, err = readLines(f)
			if err != nil {
				return err
			}
		} else {
			// Try stdin
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				urls, err = readLines(os.Stdin)
				if err != nil {
					return err
				}
			}
		}

		if len(urls) == 0 {
			return fmt.Errorf("no URLs found. Use -i <file> or pipe URLs via stdin")
		}

		opts := buildScannerOptions()
		sc, err := scanner.New(opts)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		printer, outFile := buildPrinter()
		if outFile != nil {
			defer outFile.Close()
		}

		if !flagSilent {
			fmt.Fprintf(os.Stderr, "  Loaded %d URLs  |  concurrency: %d\n\n", len(urls), flagConcurrency)
		}

		results := sc.ScanBatch(urls, func(done, total int) {
			if !flagSilent {
				pct := float64(done) / float64(total) * 100
				bar := progressBar(done, total, 30)
				fmt.Fprintf(os.Stderr, "\r  %s  %d/%d (%.0f%%)", bar, done, total, pct)
			}
		})

		if !flagSilent {
			fmt.Fprintln(os.Stderr, "\n\n  Scan complete")
		}

		printer.PrintResults(results)

		// Print summary
		if !flagSilent && flagFormat == "pretty" {
			printSummary(results)
		}

		return nil
	},
}

// ── version command ───────────────────────────────────────────────────────────

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("wapscout v%s\n", version)
		fmt.Println("powered by wappalyzergo — github.com/projectdiscovery/wappalyzergo")
	},
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func readLines(f *os.File) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func progressBar(done, total, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := done * width / total
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func printSummary(results []scanner.Result) {
	var errors, noTech, success int
	techCount := make(map[string]int)

	for _, r := range results {
		if r.Error != nil {
			errors++
			continue
		}
		if len(r.Technologies) == 0 {
			noTech++
		} else {
			success++
			for t := range r.Technologies {
				techCount[t]++
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\n  ── Summary ──────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Total scanned : %d\n", len(results))
	fmt.Fprintf(os.Stderr, "  With techs    : %d\n", success)
	fmt.Fprintf(os.Stderr, "  No techs      : %d\n", noTech)
	fmt.Fprintf(os.Stderr, "  Errors        : %d\n", errors)
	fmt.Fprintf(os.Stderr, "  Unique techs  : %d\n\n", len(techCount))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
