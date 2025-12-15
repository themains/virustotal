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

---

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