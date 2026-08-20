## Test environments

* local macOS 15.5 (aarch64), R 4.6.0
* win-builder (devel and release)
* GitHub Actions: ubuntu-latest (release, devel, oldrel-1), macOS-latest
  (release), windows-latest (release)

## R CMD check results

0 errors | 0 warnings | 0 notes

## Reverse dependencies

virustotal has one reverse dependency, rdomains, which imports `set_key()`
and `domain_report()`. Both keep their signatures and return values in this
release. Checked against rdomains with this version installed: its
`virustotal_cat()` runs and returns the expected frame, and the single test
failure in its suite is an unrelated end-to-end network test about archive
fallback.

One behavioral change is worth flagging. Earlier versions copied the
`VIRUSTOTAL_API_KEY` environment variable into `VirustotalToken` when the
package loaded; this release resolves the key when a request is made instead,
so loading the package no longer modifies the user's environment. Both
variable names still work, and `set_key()` sets both. Code outside this
package that reads `VirustotalToken` directly, as `rdomains::virustotal_cat()`
does, will not see a key set only under the canonical name and will ask for
one. The change is documented in NEWS.md, and rdomains will be updated to
read the key through this package's accessor.

## Notes on this release

The HTTP layer moved from httr to httr2, which brings request throttling,
retries that honor `Retry-After`, and a package user agent. Extra arguments
to API functions are no longer forwarded to the HTTP call and now warn; the
equivalent settings are package options, documented in `?virustotal`.
