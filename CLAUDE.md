# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an R package (`virustotal`) that provides an R client for the VirusTotal Public API v2.0 and v3.0. VirusTotal is a Google service that analyzes files and URLs for malware, provides domain categorization, and offers passive DNS information.

## Key Development Commands

### Testing
```bash
# Run all tests
R -e "devtools::test()"

# Run tests using testthat directly
R -e "testthat::test_dir('tests/testthat')"

# Run package checks (includes tests)
R CMD check .
```

### Linting
```bash
# Run lintr (mentioned in DESCRIPTION suggests)
R -e "lintr::lint_package()"
```

### Building and Installation
```bash
# Build package
R CMD build .

# Install from source
R CMD INSTALL .

# Development installation with devtools
R -e "devtools::install(build_vignettes = TRUE)"

# Build documentation
R -e "devtools::document()"

# Build pkgdown site
R -e "pkgdown::build_site()"
```

## Architecture

### Core Components

1. **Authentication**: `R/set_key.R` - Manages API key storage in environment variable `VirustotalToken`

2. **HTTP Layer**: `R/virustotal.R` - Contains base GET/POST functions:
   - `virustotal_GET()`, `virustotal_POST()` for v3 API
   - `virustotal2_GET()`, `virustotal2_POST()` for v2 API
   - `rate_limit()` enforces 4 requests/minute limit
   - `virustotal_check()` handles response validation

3. **API Endpoints**: Individual R files for each API endpoint:
   - File operations: `scan_file.R`, `file_report.R`, `rescan_file.R`
   - URL operations: `scan_url.R`, `url_report.R`
   - IP operations: `ip_report.R`, `get_ip_info.R`, `get_ip_votes.R`, etc.
   - Domain operations: `domain_report.R`, `get_domain_info.R`, etc.
   - Comments/votes: `post_comments.R`, `add_comments.R`, etc.

### Rate Limiting
The package implements automatic rate limiting via environment variable `VT_RATE_LIMIT` that tracks request count and timing to enforce VirusTotal's 4 requests/minute limit.

### API Versions
- Most functions use v2 API (`virustotal2_*` functions)
- Some newer functions use v3 API (`virustotal_*` functions)
- v3 API uses `x-apikey` header, v2 uses query parameter

## Testing Notes

Tests require a VirusTotal API key stored in `tests/testthat/virustotal_api_key.enc`. Tests are skipped on CRAN and only run when API key is available.

## Package Structure

Standard R package structure with roxygen2 documentation. Uses pkgdown for website generation. Exports 20+ functions for interacting with VirusTotal API endpoints.