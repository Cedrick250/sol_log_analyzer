package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// LogEntry is a structure to hold the parsed fields of interest.
type LogEntry struct {
	IP          string
	Path        string
	StatusCode  string
	UserAgent   string
}

// ResultItem is a generic structure for storing counted items for sorting.
type ResultItem struct {
	Value string
	Count int
}

// LogAnalyzer handles the entire analysis workflow.
type LogAnalyzer struct {
	ipCounts    map[string]int
	pathCounts  map[string]int
	statusCounts map[string]int
	agentCounts map[string]int
	// Regex for parsing a combined log format line:
	// 1. IP Address (\S+)
	// 2. Request Path (GET|POST|...) (\S+)
	// 3. Status Code (\d+)
	// 4. User Agent (.+?)
	logRegex *regexp.Regexp
}

const logURL = "https://gist.githubusercontent.com/kamranahmedse/e66c3b9ea89a1a030d3b739eeeef22d0/raw/77fb3ac837a73c4f0206e78a236d885590b7ae35/nginx-access.log"

// NewLogAnalyzer creates and initializes the analyzer.
func NewLogAnalyzer() *LogAnalyzer {
	// A robust regex to capture the required fields from the combined log format.
	// We specifically look for the request path and user agent within quotes.
	regexString := `^(\S+).*?"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s(\S+).*?"\s(\d+).*?"(?:-|\S+)"\s+"(.+?)"`
	r := regexp.MustCompile(regexString)

	return &LogAnalyzer{
		ipCounts:     make(map[string]int),
		pathCounts:   make(map[string]int),
		statusCounts: make(map[string]int),
		agentCounts:  make(map[string]int),
		logRegex:     r,
	}
}

// downloadLogFile fetches the log content from the specified URL.
func downloadLogFile(url string) (string, error) {
	fmt.Printf("Downloading log file from: %s\n", url)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching log file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download log file. Status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	return string(body), nil
}

// analyze processes the log content line by line.
func (la *LogAnalyzer) analyze(logContent string) {
	lines := strings.Split(logContent, "\n")
	fmt.Printf("Processing %d log lines...\n", len(lines))

	for _, line := range lines {
		if line == "" {
			continue
		}

		match := la.logRegex.FindStringSubmatch(line)
		if len(match) == 5 {
			// match[0] is the entire line
			entry := LogEntry{
				IP:         match[1],
				Path:       match[2],
				StatusCode: match[3],
				UserAgent:  match[4],
			}

			// Update counts
			la.ipCounts[entry.IP]++
			la.pathCounts[entry.Path]++
			la.statusCounts[entry.StatusCode]++
			la.agentCounts[entry.UserAgent]++
		}
	}
}

// getTopN converts a count map into a sorted slice of ResultItem and returns the top N.
func getTopN(counts map[string]int, n int) []ResultItem {
	var results []ResultItem
	for val, count := range counts {
		results = append(results, ResultItem{Value: val, Count: count})
	}

	// Sort the slice by count (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})

	if len(results) < n {
		return results
	}
	return results[:n]
}

// printResults prints the top N results for a given title and slice.
func printResults(title string, results []ResultItem) {
	fmt.Printf("\n%s:\n", title)
	for _, item := range results {
		fmt.Printf("%s - %d requests\n", item.Value, item.Count)
	}
}

func main() {
	// 1. Download the log file
	logContent, err := downloadLogFile(logURL)
	if err != nil {
		fmt.Printf("Fatal Error: %v\n", err)
		return
	}

	// 2. Initialize and run analysis
	analyzer := NewLogAnalyzer()
	analyzer.analyze(logContent)

	// 3. Get and print the top 5 results for each category
	const topN = 5

	// Top 5 IP addresses
	topIPs := getTopN(analyzer.ipCounts, topN)
	printResults("Top 5 IP addresses with the most requests", topIPs)

	// Top 5 most requested paths
	topPaths := getTopN(analyzer.pathCounts, topN)
	printResults("Top 5 most requested paths", topPaths)

	// Top 5 response status codes
	topStatuses := getTopN(analyzer.statusCounts, topN)
	printResults("Top 5 response status codes", topStatuses)

	// Top 5 user agents
	topAgents := getTopN(analyzer.agentCounts, topN)
	printResults("Top 5 user agents", topAgents)

	fmt.Println("\nAnalysis complete.")
}
