# virustotal (development version)

## Breaking changes

* The HTTP layer moved from httr to httr2. Extra arguments (`...`) to API
  functions are no longer forwarded to `httr::GET()`/`httr::POST()` — they
  are ignored. Configure requests with options instead:
  `virustotal.timeout` (seconds, default 60), `virustotal.max_tries`
  (default 3), `virustotal.requests_per_minute` (default 4) and
  `virustotal.throttle` (default `TRUE`).
* Error conditions now carry an httr2 response object in `$response`
  instead of an httr one. The condition classes themselves are unchanged.
* Requires R >= 4.1.0. Dependencies httr, dplyr and base64enc were dropped;
  httr2, curl and openssl were added.

## New features

* Requests identify the package with a user agent, time out after a
  configurable limit, and retry transient failures (HTTP 429/503) honoring
  the server's `Retry-After` header.
* Rate limiting moved from a hand-rolled sliding window that slept in-process
  to `httr2::req_throttle()`; the "Rate limit reached. Waiting..." message is
  gone (httr2 waits silently), and premium keys can finally raise the pace
  via `options(virustotal.requests_per_minute=)`.
* `download_file()`, `get_behaviour_html()`, `get_behaviour_evtx()`,
  `get_behaviour_pcap()` and `get_behaviour_memdump()` now go through the
  shared HTTP core: they gain rate limiting, retries and the package's
  error classes, none of which applied to them before.
* The API key is resolved lazily at call time. `VIRUSTOTAL_API_KEY` is the
  canonical environment variable and wins when both are set;
  `VirustotalToken` remains honored, and `set_key()` sets both. Loading the
  package no longer mutates environment variables.
* A missing key now raises a `virustotal_auth_error` instead of a bare
  `stop()`.

## Bug fixes

* Network failures (DNS, refused connections, timeouts) now raise a
  `virustotal_error` instead of escaping as a raw httr2 condition, so
  `tryCatch(virustotal_error = )` covers them as documented.
* A 200 response with an empty or non-JSON body (a CDN interstitial during an
  incident, say) raises a `virustotal_error` carrying the status code, rather
  than a bare jsonlite parse error.
* A server's `Retry-After` is capped at 60 seconds by default
  (`options(virustotal.max_retry_wait=)`). A `Retry-After: 3600` would
  otherwise have blocked the session for an hour before raising.
* Extra arguments passed to API functions now warn instead of vanishing
  silently, so a typo such as `cursors =` cannot leave a caller paginating
  the first page forever.
* `virustotal_info()` reports usage against the configured pace; it showed
  "used 10/4, remaining -6" for anyone who raised
  `virustotal.requests_per_minute`. Requests that reached the API and failed
  (404, 429) are now counted, since they spend quota.

* `print()` on a domain report showed the *vendors* who categorized the
  domain under the heading "Categories" — `google.com` reported
  "Categories: BitDefender, Forcepoint ThreatSeeker, Sophos, ..." The API
  keys that field by vendor and stores the category as the value, so it now
  prints the distinct categories ("search engines", ...), capped at five.

## Housekeeping

* Removed the stale `CRAN-RELEASE`/`CRAN-SUBMISSION` files, a Travis-era
  encrypted API key with no decryption code, covrpage leftovers that
  shipped in the tarball, and a permanently-skipped integration test
  (replaced by one gated on `VT_INTEGRATION=true`).
* `inst/CITATION` no longer reads a `Date` field the DESCRIPTION never had.
* Internal helpers no longer emit `message()`/`warning()` chatter during
  normal operation.

# virustotal 0.6.0

## Breaking Changes

* **Removed VirusTotal API v2.0 Support**: Completely removed all v2.0 API functions (`virustotal2_GET()`, `virustotal2_POST()`) and deprecated functions (`add_comments()`). The package now exclusively uses VirusTotal API v3.0.

## New Features

* **Analysis Endpoint**: Added `get_analysis()` to retrieve analysis results by ID.

* **File Behaviour Endpoints**: New functions for sandbox analysis:
    - `get_file_behaviour_summary()`: Summary of all behaviour reports
    - `get_file_behaviour_mitre_trees()`: MITRE ATT&CK technique mappings
    - `get_file_behaviours()`: All behaviour reports for a file

* **Sandbox Report Endpoints**: Access individual sandbox artifacts:
    - `get_behaviour_report()`: JSON behaviour report
    - `get_behaviour_html()`: HTML report from sandbox
    - `get_behaviour_evtx()`: Windows Event Log file
    - `get_behaviour_pcap()`: Network capture file
    - `get_behaviour_memdump()`: Memory dump file

## Package Simplification

* **Streamlined Architecture**: Simplified codebase by removing dual API support.
* **Enhanced Documentation**: Updated all documentation for v3.0-only support.

## Migration Guide

Users upgrading from versions that used v2.0 functions should ensure their code uses the equivalent v3.0 functions.

# virustotal 0.5.0

## Major Updates

* **Modernized Package Architecture**: Complete modernization of the virustotal package with enhanced security, error handling, and user experience.

### New Features

* **Structured Error Handling**: New S3 error classes (`virustotal_error`, `virustotal_auth_error`, `virustotal_validation_error`, `virustotal_rate_limit_error`) provide detailed error information and better debugging.

* **S3 Response Classes**: All API responses now return structured S3 objects (`virustotal_file_report`, `virustotal_domain_report`, etc.) with custom `print()` and `summary()` methods for better user experience.

* **Modern Rate Limiting**: Replaced environment variable-based rate limiting with a sliding window implementation that properly manages the 4 requests/minute VirusTotal API limit.

* **Comprehensive Input Validation**: Added robust input validation using the `checkmate` package with security-focused sanitization functions.

* **Enhanced Security Utilities**: New security functions for safe file operations and input sanitization to prevent common security issues.

### Infrastructure Improvements

* **Updated CI/CD**: Migrated from Travis CI/AppVeyor to GitHub Actions with comprehensive testing matrix (R oldrel-1, release, devel).

* **Modern Dependencies**: Updated minimum R version to 4.0.0, migrated from `plyr` to `dplyr`, added modern packages (`checkmate`, `jsonlite`, `rlang`).

* **Enhanced Documentation**: Improved documentation with roxygen2 markdown support and comprehensive examples.

* **Test Coverage**: Expanded test suite with proper mocking support and comprehensive error handling validation.

### API Enhancements

* **Improved Domain Processing**: Enhanced domain cleaning logic that properly handles URLs with protocols, www prefixes, and paths.

* **Better Error Messages**: More informative error messages with parameter context and suggested fixes.

* **Response Formatting**: Rich response formatting with detection summaries, file metadata, and threat intelligence display.

### Breaking Changes

* Minimum R version increased from 3.3.0 to 4.0.0
* Some internal functions have been refactored (not user-facing)
* Error objects now use structured S3 classes instead of simple character strings

### Bug Fixes

* Fixed rate limiting edge cases and timing issues
* Improved handling of malformed API responses
* Enhanced validation precedence for better test compatibility
* Fixed Unicode character encoding in utility functions

### Development Tools

* Added `virustotal_info()` function for package configuration diagnostics
* Enhanced rate limit status reporting with `get_rate_limit_status()`
* Improved temporary file management with security-focused utilities

# virustotal 0.3.0

## Major Changes
* **BREAKING**: Migrated all core functions to VirusTotal API v3
* **BREAKING**: Function return types changed from data.frame to list (following v3 API structure)
* Updated all functions: `file_report()`, `scan_file()`, `rescan_file()`, `url_report()`, `scan_url()`, `domain_report()`, `ip_report()`
* Removed deprecated `virustotal2_*` function calls from user-facing functions

## New Features
* Enhanced input validation for all functions
* Automatic URL encoding for v3 API compatibility
* Improved error messages with actionable guidance
* Support for IPv6 addresses in `ip_report()`
* Domain name normalization (removes protocols, www, paths)

## Testing & Quality
* Comprehensive test suite with 47+ tests
* Added input validation tests for all core functions
* Proper error handling tests
* GitHub Actions CI/CD pipeline replacing AppVeyor
* Multi-platform testing (Ubuntu, Windows, macOS)
* Automated test coverage reporting

## Documentation
* Updated all function documentation for v3 API
* Comprehensive vignette rewrite with modern examples
* Updated references to point to current VirusTotal documentation
* Added usage examples for all major functions

## Dependencies
* Added `base64enc` for URL encoding support
* Updated imports and suggests for modern R ecosystem

# virustotal 0.2.2

* support for domain and ip v3
* deprecate v2 domain and ip functions 

# virustotal 0.2.1

* extensive linting, passes expect_no_lint
* url_report now returns service name

# virustotal 0.2.0

* Removed link to bitdefender because CRAN was having issues
* Better documentation with examples including comment for set_key, better formatting
* Better error handling and more consistent returned data structures for url_report, file_report, rescan_file 
* url_report now accepts scan_id as a param
* Warning messages end with new line
* Added more tests, specifically checking returns to what happens when params/hash are incorrect  
* Enforces rate limiting --- 4 queries per minute. 
* Graceful error handling if error limit exceeded.
* changed virustotal to VirusTotal as CRAN doesn't muck around.
 
# virustotal 0.1.0

* Initial release