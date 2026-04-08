package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Result holds the detection results for a single URL
type Result struct {
	URL          string
	FinalURL     string
	StatusCode   int
	Technologies map[string]wappalyzer.AppInfo
	Headers      http.Header
	Error        error
	Duration     time.Duration
}

// Options configures the scanner behavior
type Options struct {
	Timeout        time.Duration
	FollowRedirect bool
	MaxRedirects   int
	UserAgent      string
	Proxy          string
	InsecureSkip   bool
	Headers        map[string]string
	Concurrency    int
}

// DefaultOptions returns sensible defaults
func DefaultOptions() Options {
	return Options{
		Timeout:        15 * time.Second,
		FollowRedirect: true,
		MaxRedirects:   10,
		UserAgent:      "Mozilla/5.0 (compatible; WapScout/1.0; +https://github.com/wapscout)",
		InsecureSkip:   false,
		Concurrency:    5,
	}
}

// Scanner performs technology detection
type Scanner struct {
	client    *http.Client
	wapClient *wappalyzer.Wappalyze
	opts      Options
}

// New creates a new Scanner instance
func New(opts Options) (*Scanner, error) {
	wapClient, err := wappalyzer.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize wappalyzer: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureSkip,
		},
		DisableKeepAlives: false,
		MaxIdleConns:      100,
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if !opts.FollowRedirect {
			return http.ErrUseLastResponse
		}
		if len(via) >= opts.MaxRedirects {
			return fmt.Errorf("too many redirects (max %d)", opts.MaxRedirects)
		}
		return nil
	}

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: redirectPolicy,
		Timeout:       opts.Timeout,
	}

	return &Scanner{
		client:    client,
		wapClient: wapClient,
		opts:      opts,
	}, nil
}

// Scan analyzes a single URL and returns the detected technologies
func (s *Scanner) Scan(rawURL string) Result {
	start := time.Now()
	result := Result{URL: rawURL}

	// Normalize URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	result.URL = rawURL

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to create request: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	req.Header.Set("User-Agent", s.opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	for k, v := range s.opts.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Headers = resp.Header
	if resp.Request != nil {
		result.FinalURL = resp.Request.URL.String()
	} else {
		result.FinalURL = rawURL
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		result.Error = fmt.Errorf("failed to read body: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Technologies = s.wapClient.FingerprintWithInfo(resp.Header, body)
	result.Duration = time.Since(start)
	return result
}

// ScanBatch scans multiple URLs concurrently
func (s *Scanner) ScanBatch(urls []string, progress func(done, total int)) []Result {
	results := make([]Result, len(urls))
	sem := make(chan struct{}, s.opts.Concurrency)
	done := make(chan struct{}, len(urls))

	for i, u := range urls {
		go func(idx int, target string) {
			sem <- struct{}{}
			results[idx] = s.Scan(target)
			<-sem
			done <- struct{}{}
		}(i, u)
	}

	completed := 0
	for range urls {
		<-done
		completed++
		if progress != nil {
			progress(completed, len(urls))
		}
	}

	return results
}
