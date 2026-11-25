## Reason for update

This release keeps the API key on the VirusTotal API origin during file
transfers and corrects the hostname used for domain reports and rescans.
It also bundles the URL, relationship, vote, and error-handling fixes
documented in NEWS.

## Local checks for 0.8.0

On macOS 27.0.1 (arm64), R 4.6.0, the built source package passed
R CMD check --as-cran with 0 errors, 0 warnings, and 0 notes.
The development suite passed 632 assertions with httr2 1.2.2 and again
with httr2 1.3.0. Two checks that require a configured VirusTotal key
were skipped in each run.

## Reverse dependency

CRAN rdomains 0.6.1 passed R CMD check in separate libraries using
virustotal 0.7.1 and 0.8.0. Both runs passed 518 assertions and skipped 23.
