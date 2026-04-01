## Test environments
* Local macOS (aarch64-apple-darwin20), R 4.5.2
* win-builder (R-devel)
* win-builder (R-release)

## R CMD check results
0 errors | 0 warnings | 1 note

* NOTE: "IoC" flagged as possibly misspelled in DESCRIPTION
  - This is intentional: IoC = "Indicator of Compromise" (standard security term)

## New in this version
* Removed VirusTotal API v2.0 support (package now uses v3.0 exclusively)
* Added 9 new behaviour/analysis endpoints
* Bug fix: get_domain_comments() recursive argument issue
