## Test environments

* Local macOS 27.0.1 (aarch64), R 4.6.0.
* GitHub Actions: Ubuntu R 4.6.2 and R 4.5.3; macOS and Windows R 4.6.2.
* R-hub: Ubuntu clang R-devel and Windows R-devel.

## R CMD check results

0 errors | 0 warnings | 0 notes

The offline suite passes with current httr2 and the minimum supported version,
1.2.2. Retry and multipart-upload tests run against local HTTP/HTTPS servers.
Live VirusTotal tests require credentials and are skipped.

## Reverse dependencies

Full R CMD check --as-cran checks of CRAN rdomains 0.6.1 were compared using
virustotal 0.7.0 and 0.7.1 in separate libraries. There are no new errors,
warnings, or notes; both test runs pass 518 assertions. Both checks report
the same incoming-version warning because rdomains 0.6.1 is already on CRAN.
