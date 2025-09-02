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