## Release Summary
This is a major version update (0.2.2 -> 0.3.0) that migrates the package from VirusTotal API v2 to v3.

### Major Changes
- **BREAKING CHANGE**: All core functions now use VirusTotal API v3
- **BREAKING CHANGE**: Return types changed from data.frame to list (following v3 API structure)  
- Enhanced input validation and error handling
- Comprehensive test suite with 47+ tests
- Updated documentation and examples

## Test environments
* local macOS (Apple Silicon), R 4.5.1
* GitHub Actions: ubuntu-latest, windows-latest, macOS-latest with R release and devel
* R CMD check --as-cran: PASS

## R CMD check results
There were no ERRORs or WARNINGs.

There are 3 NOTEs:
1. **CRAN incoming feasibility**: Found possibly invalid URLs that redirect but are functional
2. **Non-standard files**: CLAUDE.md (development file) and Citation.cff (GitHub citation file) 
3. **HTML manual**: HTML Tidy version message (informational only)

All NOTEs are acceptable and don't affect package functionality.

