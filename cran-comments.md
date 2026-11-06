## Test environment

Local macOS 27.0.1 (aarch64), R 4.6.0; checked November 5, 2026.

## R CMD check results

0 errors | 0 warnings | 1 NOTE

* Version contains large components (0.7.0.9000).

This is a development version. The release version needs fresh platform CI
and Windows devel checks before submission.

## Tests

The local suite passes with current httr2 and the minimum supported version,
1.2.2. Retry and upload tests use local HTTP/HTTPS servers. Live VirusTotal
tests require credentials and were not run.

## Reverse dependencies

Targeted tests from CRAN rdomains 0.6.1 pass, as does a mocked integration
through its `virustotal_cat()` and this package's `domain_report()`.
A full reverse-dependency check is still required before submission.
