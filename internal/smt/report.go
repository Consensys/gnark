package smt

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

// ReportFormat specifies the output format for reports.
type ReportFormat int

const (
	// FormatText outputs plain text
	FormatText ReportFormat = iota
	// FormatTerminal outputs text with ANSI colors
	FormatTerminal
	// FormatHTML outputs an HTML report
	FormatHTML
	// FormatJSON outputs machine-readable JSON
	FormatJSON
)

// Report contains all information for generating analysis reports.
type Report struct {
	// Circuit information
	CircuitName string `json:"circuit_name"`
	Field       string `json:"field"`

	// Variable counts
	NbPublic   int `json:"nb_public"`
	NbSecret   int `json:"nb_secret"`
	NbInternal int `json:"nb_internal"`

	// Constraint information
	NbConstraints int      `json:"nb_constraints"`
	Patterns      []string `json:"patterns"`

	// Analysis results
	Issues []ReportIssue `json:"issues"`
	Passed []string      `json:"passed"`

	// Debug information
	DebugInfo *ExtractedDebugInfo `json:"-"`

	// Constraint details (optional, for detailed reports)
	Constraints []ExtractedConstraint `json:"-"`
}

// ReportIssue represents an issue with source location.
type ReportIssue struct {
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Details     string `json:"details,omitempty"`

	// Location information
	ConstraintIndex int    `json:"constraint_index,omitempty"`
	VariableIndex   int    `json:"variable_index,omitempty"`
	VariableName    string `json:"variable_name,omitempty"`
	SourceLocation  string `json:"source_location,omitempty"`
}

// NewReport creates a new report from analysis results.
func NewReport(ext *ExtractedSystem, analysis *AnalysisResult, debugInfo *ExtractedDebugInfo) *Report {
	report := &Report{
		CircuitName:   analysis.CircuitName,
		Field:         ext.Field.String()[:20] + "...",
		NbPublic:      ext.NbPublic,
		NbSecret:      ext.NbSecret,
		NbInternal:    ext.NbInternal,
		NbConstraints: len(ext.Constraints),
		Patterns:      AnalyzeConstraintPatterns(ext),
		Passed:        analysis.Passed,
		DebugInfo:     debugInfo,
		Constraints:   ext.Constraints,
	}

	// Convert issues with source locations
	for _, issue := range analysis.Issues {
		ri := ReportIssue{
			Severity:        issue.Severity,
			Type:            issue.Type,
			Description:     issue.Description,
			Details:         issue.Details,
			ConstraintIndex: issue.ConstraintIndex,
			VariableIndex:   issue.VariableIndex,
		}

		// Add variable name if available
		if issue.VariableIndex >= 0 && issue.VariableIndex < len(ext.VariableNames) {
			ri.VariableName = ext.VariableNames[issue.VariableIndex]
		}

		// Add source location if available
		if debugInfo != nil {
			if issue.ConstraintIndex >= 0 {
				ri.SourceLocation = debugInfo.GetConstraintLocation(issue.ConstraintIndex)
			} else if issue.VariableIndex >= 0 {
				ri.SourceLocation = debugInfo.GetVariableLocation(issue.VariableIndex, ext.Constraints)
			}
		}

		report.Issues = append(report.Issues, ri)
	}

	return report
}

// Write outputs the report in the specified format.
func (r *Report) Write(w io.Writer, format ReportFormat) error {
	switch format {
	case FormatText:
		return r.writeText(w, false)
	case FormatTerminal:
		return r.writeText(w, true)
	case FormatHTML:
		return r.writeHTML(w)
	case FormatJSON:
		return r.writeJSON(w)
	default:
		return r.writeText(w, false)
	}
}

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

func (r *Report) writeText(w io.Writer, useColors bool) error {
	// Helper for conditional coloring
	color := func(c, text string) string {
		if useColors {
			return c + text + colorReset
		}
		return text
	}

	bold := func(text string) string {
		return color(colorBold, text)
	}

	// Header
	fmt.Fprintln(w)
	fmt.Fprintln(w, bold("╔══════════════════════════════════════════════════════════════════════════════╗"))
	fmt.Fprintf(w, bold("║")+"  SMT Soundness Analysis: %-50s"+bold("║")+"\n", r.CircuitName)
	fmt.Fprintln(w, bold("╚══════════════════════════════════════════════════════════════════════════════╝"))
	fmt.Fprintln(w)

	// Circuit info
	fmt.Fprintln(w, bold("Circuit Information"))
	fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────────────────────")
	fmt.Fprintf(w, "  Field:        %s\n", r.Field)
	fmt.Fprintf(w, "  Public vars:  %s\n", color(colorCyan, fmt.Sprintf("%d", r.NbPublic)))
	fmt.Fprintf(w, "  Secret vars:  %s\n", color(colorCyan, fmt.Sprintf("%d", r.NbSecret)))
	fmt.Fprintf(w, "  Internal vars:%s\n", color(colorCyan, fmt.Sprintf("%d", r.NbInternal)))
	fmt.Fprintf(w, "  Constraints:  %s\n", color(colorCyan, fmt.Sprintf("%d", r.NbConstraints)))
	fmt.Fprintln(w)

	// Constraint patterns
	if len(r.Patterns) > 0 {
		fmt.Fprintln(w, bold("Constraint Patterns"))
		fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────────────────────")
		for _, p := range r.Patterns {
			fmt.Fprintf(w, "  • %s\n", p)
		}
		fmt.Fprintln(w)
	}

	// Count issues by severity
	criticalCount := 0
	warningCount := 0
	infoCount := 0
	for _, issue := range r.Issues {
		switch issue.Severity {
		case "critical":
			criticalCount++
		case "warning":
			warningCount++
		case "info":
			infoCount++
		}
	}

	// Summary
	fmt.Fprintln(w, bold("Analysis Summary"))
	fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────────────────────")

	if criticalCount > 0 {
		fmt.Fprintf(w, "  %s  %d critical issues\n", color(colorRed, "●"), criticalCount)
	}
	if warningCount > 0 {
		fmt.Fprintf(w, "  %s  %d warnings\n", color(colorYellow, "●"), warningCount)
	}
	if infoCount > 0 {
		fmt.Fprintf(w, "  %s  %d info\n", color(colorBlue, "●"), infoCount)
	}
	if len(r.Passed) > 0 {
		fmt.Fprintf(w, "  %s  %d passed checks\n", color(colorGreen, "●"), len(r.Passed))
	}
	fmt.Fprintln(w)

	// Passed checks
	if len(r.Passed) > 0 {
		fmt.Fprintln(w, bold("Passed Checks"))
		fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────────────────────")
		for _, p := range r.Passed {
			fmt.Fprintf(w, "  %s %s\n", color(colorGreen, "✓"), p)
		}
		fmt.Fprintln(w)
	}

	// Issues
	if len(r.Issues) > 0 {
		fmt.Fprintln(w, bold("Issues Found"))
		fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────────────────────")

		// Group by severity
		grouped := map[string][]ReportIssue{
			"critical": {},
			"warning":  {},
			"info":     {},
		}
		for _, issue := range r.Issues {
			grouped[issue.Severity] = append(grouped[issue.Severity], issue)
		}

		// Print critical first
		for _, severity := range []string{"critical", "warning", "info"} {
			issues := grouped[severity]
			if len(issues) == 0 {
				continue
			}

			var severityColor, icon string
			switch severity {
			case "critical":
				severityColor = colorRed
				icon = "✗"
			case "warning":
				severityColor = colorYellow
				icon = "⚠"
			case "info":
				severityColor = colorBlue
				icon = "ℹ"
			}

			for i, issue := range issues {
				fmt.Fprintf(w, "\n  %s %s\n",
					color(severityColor, icon),
					color(severityColor+colorBold, fmt.Sprintf("[%s] %s", strings.ToUpper(severity), issue.Type)))

				fmt.Fprintf(w, "     %s\n", issue.Description)

				if issue.VariableName != "" {
					fmt.Fprintf(w, "     Variable: %s\n", color(colorCyan, issue.VariableName))
				}

				if issue.SourceLocation != "" {
					fmt.Fprintf(w, "     Location: %s\n", color(colorMagenta, issue.SourceLocation))
				}

				if issue.Details != "" {
					fmt.Fprintf(w, "     %s\n", color(colorDim, issue.Details))
				}

				if i < len(issues)-1 {
					fmt.Fprintln(w)
				}
			}
		}
		fmt.Fprintln(w)
	}

	// Final result
	fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────────────────────")
	if criticalCount > 0 {
		fmt.Fprintf(w, "Result: %s\n", color(colorRed+colorBold, "CRITICAL ISSUES FOUND"))
	} else if warningCount > 0 {
		fmt.Fprintf(w, "Result: %s\n", color(colorYellow+colorBold, "WARNINGS FOUND"))
	} else {
		fmt.Fprintf(w, "Result: %s\n", color(colorGreen+colorBold, "PASSED"))
	}
	fmt.Fprintln(w)

	return nil
}

func (r *Report) writeHTML(w io.Writer) error {
	// Count issues
	criticalCount := 0
	warningCount := 0
	infoCount := 0
	for _, issue := range r.Issues {
		switch issue.Severity {
		case "critical":
			criticalCount++
		case "warning":
			warningCount++
		case "info":
			infoCount++
		}
	}

	resultClass := "passed"
	resultText := "PASSED"
	if criticalCount > 0 {
		resultClass = "critical"
		resultText = "CRITICAL ISSUES FOUND"
	} else if warningCount > 0 {
		resultClass = "warning"
		resultText = "WARNINGS FOUND"
	}

	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMT Soundness Analysis - `+html.EscapeString(r.CircuitName)+`</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent-red: #e94560;
            --accent-yellow: #f4d160;
            --accent-green: #4ade80;
            --accent-blue: #60a5fa;
            --accent-cyan: #22d3ee;
            --accent-purple: #a78bfa;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent-purple);
        }

        h2 {
            font-size: 1.1rem;
            margin: 1.5rem 0 0.75rem;
            color: var(--accent-cyan);
        }

        .card {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--accent-purple);
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }

        .info-item label {
            color: var(--text-secondary);
            font-size: 0.85rem;
        }

        .info-item .value {
            font-size: 1.2rem;
            color: var(--accent-cyan);
        }

        .summary-badges {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }

        .badge {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: bold;
        }

        .badge.critical { background: rgba(233, 69, 96, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .badge.warning { background: rgba(244, 209, 96, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .badge.info { background: rgba(96, 165, 250, 0.2); color: var(--accent-blue); border: 1px solid var(--accent-blue); }
        .badge.passed { background: rgba(74, 222, 128, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }

        .result-banner {
            padding: 1rem 1.5rem;
            border-radius: 8px;
            font-size: 1.1rem;
            font-weight: bold;
            text-align: center;
            margin-top: 1rem;
        }

        .result-banner.critical { background: rgba(233, 69, 96, 0.3); color: var(--accent-red); }
        .result-banner.warning { background: rgba(244, 209, 96, 0.3); color: var(--accent-yellow); }
        .result-banner.passed { background: rgba(74, 222, 128, 0.3); color: var(--accent-green); }

        .issue {
            background: var(--bg-card);
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 0.75rem;
            border-left: 4px solid;
        }

        .issue.critical { border-color: var(--accent-red); }
        .issue.warning { border-color: var(--accent-yellow); }
        .issue.info { border-color: var(--accent-blue); }

        .issue-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }

        .issue-type {
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8rem;
        }

        .issue.critical .issue-type { color: var(--accent-red); }
        .issue.warning .issue-type { color: var(--accent-yellow); }
        .issue.info .issue-type { color: var(--accent-blue); }

        .issue-description { margin-bottom: 0.5rem; }

        .issue-meta {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .issue-meta span {
            display: inline-block;
            margin-right: 1rem;
        }

        .issue-meta .variable { color: var(--accent-cyan); }
        .issue-meta .location { color: var(--accent-purple); }

        .issue-details {
            margin-top: 0.5rem;
            padding-top: 0.5rem;
            border-top: 1px dashed var(--bg-primary);
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .patterns {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .pattern {
            background: var(--bg-card);
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }

        .passed-list {
            list-style: none;
        }

        .passed-list li {
            padding: 0.25rem 0;
            color: var(--accent-green);
        }

        .passed-list li::before {
            content: "✓ ";
        }

        .collapsible {
            cursor: pointer;
        }

        .collapsible:hover {
            opacity: 0.9;
        }

        .collapsed-content {
            display: none;
        }

        .collapsed-content.show {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SMT Soundness Analysis</h1>
        <p style="color: var(--text-secondary); margin-bottom: 1rem;">Circuit: <strong style="color: var(--accent-cyan);">`)
	fmt.Fprint(w, html.EscapeString(r.CircuitName))
	fmt.Fprint(w, `</strong></p>

        <div class="card">
            <h2>Circuit Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <label>Public Variables</label>
                    <div class="value">`)
	fmt.Fprintf(w, "%d", r.NbPublic)
	fmt.Fprint(w, `</div>
                </div>
                <div class="info-item">
                    <label>Secret Variables</label>
                    <div class="value">`)
	fmt.Fprintf(w, "%d", r.NbSecret)
	fmt.Fprint(w, `</div>
                </div>
                <div class="info-item">
                    <label>Internal Variables</label>
                    <div class="value">`)
	fmt.Fprintf(w, "%d", r.NbInternal)
	fmt.Fprint(w, `</div>
                </div>
                <div class="info-item">
                    <label>Constraints</label>
                    <div class="value">`)
	fmt.Fprintf(w, "%d", r.NbConstraints)
	fmt.Fprint(w, `</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Constraint Patterns</h2>
            <div class="patterns">`)
	for _, p := range r.Patterns {
		fmt.Fprintf(w, `<span class="pattern">%s</span>`, html.EscapeString(p))
	}
	fmt.Fprint(w, `
            </div>
        </div>

        <div class="card">
            <h2>Analysis Summary</h2>
            <div class="summary-badges">`)
	if criticalCount > 0 {
		fmt.Fprintf(w, `<span class="badge critical">%d Critical</span>`, criticalCount)
	}
	if warningCount > 0 {
		fmt.Fprintf(w, `<span class="badge warning">%d Warnings</span>`, warningCount)
	}
	if infoCount > 0 {
		fmt.Fprintf(w, `<span class="badge info">%d Info</span>`, infoCount)
	}
	if len(r.Passed) > 0 {
		fmt.Fprintf(w, `<span class="badge passed">%d Passed</span>`, len(r.Passed))
	}
	fmt.Fprint(w, `
            </div>
            <div class="result-banner `+resultClass+`">`+resultText+`</div>
        </div>`)

	// Passed checks
	if len(r.Passed) > 0 {
		fmt.Fprint(w, `
        <div class="card">
            <h2>Passed Checks</h2>
            <ul class="passed-list">`)
		for _, p := range r.Passed {
			// Only show first 10 passed checks
			fmt.Fprintf(w, `<li>%s</li>`, html.EscapeString(p))
		}
		fmt.Fprint(w, `
            </ul>
        </div>`)
	}

	// Issues
	if len(r.Issues) > 0 {
		fmt.Fprint(w, `
        <div class="card">
            <h2>Issues Found</h2>`)

		// Sort issues by severity
		sortedIssues := make([]ReportIssue, len(r.Issues))
		copy(sortedIssues, r.Issues)
		sort.Slice(sortedIssues, func(i, j int) bool {
			severityOrder := map[string]int{"critical": 0, "warning": 1, "info": 2}
			return severityOrder[sortedIssues[i].Severity] < severityOrder[sortedIssues[j].Severity]
		})

		for _, issue := range sortedIssues {
			fmt.Fprintf(w, `
            <div class="issue %s">
                <div class="issue-header">
                    <span class="issue-type">[%s] %s</span>
                </div>
                <div class="issue-description">%s</div>
                <div class="issue-meta">`,
				issue.Severity,
				strings.ToUpper(issue.Severity),
				html.EscapeString(issue.Type),
				html.EscapeString(issue.Description))

			if issue.VariableName != "" {
				fmt.Fprintf(w, `<span class="variable">Variable: %s</span>`, html.EscapeString(issue.VariableName))
			}
			if issue.SourceLocation != "" {
				fmt.Fprintf(w, `<span class="location">📍 %s</span>`, html.EscapeString(issue.SourceLocation))
			}

			fmt.Fprint(w, `</div>`)

			if issue.Details != "" {
				fmt.Fprintf(w, `<div class="issue-details">%s</div>`, html.EscapeString(issue.Details))
			}

			fmt.Fprint(w, `</div>`)
		}

		fmt.Fprint(w, `
        </div>`)
	}

	fmt.Fprint(w, `
    </div>

    <script>
        // Make passed checks collapsible if there are many
        document.querySelectorAll('.collapsible').forEach(el => {
            el.addEventListener('click', () => {
                const content = el.nextElementSibling;
                content.classList.toggle('show');
            });
        });
    </script>
</body>
</html>`)

	return nil
}

func (r *Report) writeJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// ShortenPath shortens a file path for display.
func ShortenPath(path string) string {
	if path == "" {
		return ""
	}
	// Try to shorten to just filename and parent dir
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	parent := filepath.Base(dir)
	if parent != "" && parent != "." {
		return parent + "/" + base
	}
	return base
}
