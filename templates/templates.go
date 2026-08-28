package templates

import (
	_ "embed"
)

// DefaultHTMLReportTemplate embeds the HTML SOC Dashboard report template directly into the binary.
// This ensures that the binary is completely standalone on Windows, Linux, and macOS without requiring
// external template files in the current working directory.
//
//go:embed report.html.tmpl
var DefaultHTMLReportTemplate string
