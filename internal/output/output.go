package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"wapscout/internal/scanner"

	"github.com/fatih/color"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Format defines the output format type
type Format string

const (
	FormatPretty Format = "pretty"
	FormatJSON   Format = "json"
	FormatCSV    Format = "csv"
	FormatPlain  Format = "plain"
)

var (
	bold    = color.New(color.Bold)
	cyan    = color.New(color.FgCyan, color.Bold)
	green   = color.New(color.FgGreen)
	yellow  = color.New(color.FgYellow)
	red     = color.New(color.FgRed)
	magenta = color.New(color.FgMagenta)
	white   = color.New(color.FgWhite, color.Bold)
	dim     = color.New(color.Faint)
)

// Printer handles output rendering
type Printer struct {
	Format   Format
	NoColor  bool
	ShowMeta bool
	Output   *os.File
}

// NewPrinter creates a new Printer
func NewPrinter(format Format, noColor bool, showMeta bool, outputFile *os.File) *Printer {
	if noColor {
		color.NoColor = true
	}
	if outputFile == nil {
		outputFile = os.Stdout
	}
	return &Printer{Format: format, NoColor: noColor, ShowMeta: showMeta, Output: outputFile}
}

// PrintBanner prints the tool banner
func PrintBanner() {
	banner := `
  ██╗    ██╗ █████╗ ██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ██║    ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██║ █╗ ██║███████║██████╔╝███████╗██║     ██║   ██║██║   ██║   ██║   
  ██║███╗██║██╔══██║██╔═══╝ ╚════██║██║     ██║   ██║██║   ██║   ██║   
  ╚███╔███╔╝██║  ██║██║     ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   `

	cyan.Fprintln(os.Stderr, banner)
	dim.Fprintln(os.Stderr, "                   Technology Detection CLI  |  powered by wappalyzergo")
}

// PrintResult renders a single scan result
func (p *Printer) PrintResult(result scanner.Result) {
	switch p.Format {
	case FormatJSON:
		p.printJSON(result)
	case FormatCSV:
		p.printCSV(result)
	case FormatPlain:
		p.printPlain(result)
	default:
		p.printPretty(result)
	}
}

// PrintResults renders multiple scan results
func (p *Printer) PrintResults(results []scanner.Result) {
	switch p.Format {
	case FormatJSON:
		p.printJSONArray(results)
	case FormatCSV:
		p.printCSVHeader()
		for _, r := range results {
			p.printCSV(r)
		}
	default:
		for _, r := range results {
			p.PrintResult(r)
		}
	}
}

// ---- Pretty output ----

func (p *Printer) printPretty(result scanner.Result) {
	fmt.Fprintln(p.Output)
	p.printSeparator()

	// URL line
	white.Fprintf(p.Output, "  URL      : ")
	cyan.Fprintln(p.Output, result.URL)

	if result.FinalURL != "" && result.FinalURL != result.URL {
		white.Fprintf(p.Output, "  Redirect : ")
		dim.Fprintln(p.Output, result.FinalURL)
	}

	// Status
	white.Fprintf(p.Output, "  Status   : ")
	p.printStatus(result.StatusCode)

	// Duration
	white.Fprintf(p.Output, "  Duration : ")
	dim.Fprintf(p.Output, "%s\n", result.Duration.Round(1000000))

	if result.Error != nil {
		red.Fprintf(p.Output, "  Error    : %s\n", result.Error)
		p.printSeparator()
		return
	}

	// Technologies
	if len(result.Technologies) == 0 {
		yellow.Fprintln(p.Output, "\n  No technologies detected")
	} else {
		fmt.Fprintf(p.Output, "\n  ")
		green.Fprintf(p.Output, "Technologies detected (%d):\n\n", len(result.Technologies))

		// Group by category
		cats := groupByCategory(result.Technologies)
		catNames := sortedKeys(cats)

		for _, cat := range catNames {
			techs := cats[cat]
			magenta.Fprintf(p.Output, "    ┌─ %s\n", cat)
			for i, name := range techs {
				info := result.Technologies[name]
				prefix := "    ├─ "
				if i == len(techs)-1 {
					prefix = "    └─ "
				}
				green.Fprintf(p.Output, "%s", prefix)
				bold.Fprintf(p.Output, "%s", name)
				if p.ShowMeta && len(info.Categories) > 0 {
					dim.Fprintf(p.Output, " (%s)", strings.Join(info.Categories, ", "))
				}
				fmt.Fprintln(p.Output)
			}
			fmt.Fprintln(p.Output)
		}
	}

	if p.ShowMeta {
		p.printHeaders(result)
	}

	p.printSeparator()
}

func (p *Printer) printHeaders(result scanner.Result) {
	if len(result.Headers) == 0 {
		return
	}
	white.Fprintln(p.Output, "\n  Response Headers:")
	w := tabwriter.NewWriter(p.Output, 0, 0, 2, ' ', 0)
	keys := make([]string, 0, len(result.Headers))
	for k := range result.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dim.Fprintf(w, "    %s\t%s\n", k, strings.Join(result.Headers[k], "; "))
	}
	w.Flush()
}

func (p *Printer) printStatus(code int) {
	switch {
	case code >= 200 && code < 300:
		green.Fprintf(p.Output, "%d\n", code)
	case code >= 300 && code < 400:
		yellow.Fprintf(p.Output, "%d\n", code)
	case code >= 400:
		red.Fprintf(p.Output, "%d\n", code)
	default:
		dim.Fprintf(p.Output, "%d\n", code)
	}
}

func (p *Printer) printSeparator() {
	dim.Fprintln(p.Output, "  "+strings.Repeat("─", 60))
}

// ---- JSON output ----

type jsonResult struct {
	URL          string                        `json:"url"`
	FinalURL     string                        `json:"final_url,omitempty"`
	StatusCode   int                           `json:"status_code"`
	Duration     string                        `json:"duration"`
	Technologies map[string]wappalyzer.AppInfo `json:"technologies"`
	Error        string                        `json:"error,omitempty"`
}

func (p *Printer) printJSON(result scanner.Result) {
	out := jsonResult{
		URL:          result.URL,
		FinalURL:     result.FinalURL,
		StatusCode:   result.StatusCode,
		Duration:     result.Duration.String(),
		Technologies: result.Technologies,
	}
	if result.Error != nil {
		out.Error = result.Error.Error()
	}
	enc := json.NewEncoder(p.Output)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func (p *Printer) printJSONArray(results []scanner.Result) {
	out := make([]jsonResult, len(results))
	for i, r := range results {
		out[i] = jsonResult{
			URL:          r.URL,
			FinalURL:     r.FinalURL,
			StatusCode:   r.StatusCode,
			Duration:     r.Duration.String(),
			Technologies: r.Technologies,
		}
		if r.Error != nil {
			out[i].Error = r.Error.Error()
		}
	}
	enc := json.NewEncoder(p.Output)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// ---- CSV output ----

func (p *Printer) printCSVHeader() {
	fmt.Fprintf(p.Output, "url,final_url,status_code,duration,technology,version,categories\n")
}

func (p *Printer) printCSV(result scanner.Result) {
	errStr := ""
	if result.Error != nil {
		errStr = result.Error.Error()
	}

	if len(result.Technologies) == 0 {
		fmt.Fprintf(p.Output, "%s,%s,%d,%s,,,\"%s\"\n",
			csvEscape(result.URL),
			csvEscape(result.FinalURL),
			result.StatusCode,
			result.Duration,
			csvEscape(errStr),
		)
		return
	}

	for name, info := range result.Technologies {
		fmt.Fprintf(p.Output, "%s,%s,%d,%s,%s,%s,\"%s\"\n",
			csvEscape(result.URL),
			csvEscape(result.FinalURL),
			result.StatusCode,
			result.Duration,
			csvEscape(name),
			"",
			csvEscape(strings.Join(info.Categories, "|")),
		)
	}
}

// ---- Plain output ----

func (p *Printer) printPlain(result scanner.Result) {
	if result.Error != nil {
		fmt.Fprintf(p.Output, "[ERROR] %s: %s\n", result.URL, result.Error)
		return
	}
	techs := sortedKeys2(result.Technologies)
	for _, t := range techs {
		fmt.Fprintf(p.Output, "%s [%s]\n", result.URL, t)
	}
}

// ---- Helpers ----

func groupByCategory(techs map[string]wappalyzer.AppInfo) map[string][]string {
	cats := make(map[string][]string)
	for name, info := range techs {
		if len(info.Categories) == 0 {
			cats["Uncategorized"] = append(cats["Uncategorized"], name)
		} else {
			for _, c := range info.Categories {
				cats[c] = append(cats[c], name)
			}
		}
	}
	for k := range cats {
		sort.Strings(cats[k])
	}
	return cats
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeys2(m map[string]wappalyzer.AppInfo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
