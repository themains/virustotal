## virustotal: R Client for the VirusTotal Public API v2.0 and v3.0

[![R-CMD-check](https://github.com/themains/virustotal/actions/workflows/R-CMD-check.yml/badge.svg)](https://github.com/themains/virustotal/actions/workflows/R-CMD-check.yml)
[![pkgdown](https://github.com/themains/virustotal/actions/workflows/pkgdown.yml/badge.svg)](https://github.com/themains/virustotal/actions/workflows/pkgdown.yml)
[![CRAN_Status_Badge](https://www.r-pkg.org/badges/version/virustotal)](https://cran.r-project.org/package=virustotal)
![](https://cranlogs.r-pkg.org/badges/grand-total/virustotal)


Use [VirusTotal](https://www.virustotal.com), a Google service that analyzes files and URLs for viruses, worms, trojans etc., provides category of the content hosted by a domain from a variety of prominent services, provides passive DNS information, among other things.

This package supports both VirusTotal API v2.0 (legacy) and v3.0 (current). The v3.0 API provides richer data including IoC relationships, sandbox dynamic analysis, static file information, YARA rules, and more comprehensive threat intelligence.

**API Rate Limits:**
- **Public API**: 500 requests/day, 4 requests/minute
- **Premium API**: No daily or rate limitations

**Supported Operations:**
- **Files**: Upload, scan, get reports, download, comments, votes, relationships
- **URLs**: Submit for analysis, get reports, comments, votes, relationships  
- **Domains**: Get reports, comments, votes, relationships, WHOIS data
- **IP Addresses**: Get reports, comments, votes, relationships, passive DNS

See [https://www.virustotal.com](https://www.virustotal.com) for more information. 

### Installation

To get the current released version from CRAN:
```r
install.packages("virustotal")
```

To get the current development version from GitHub:

```r
install.packages("devtools")
devtools::install_github("themains/virustotal", build_vignettes = TRUE)
```

### Usage

To learn about how to use the package, read the [vignette](vignettes/using_virustotal.Rmd). Or launch the vignette within R:

```r
# Using virustotal
vignette("using_virustotal", package = "virustotal")
```

### License
Scripts are released under the [MIT License](https://opensource.org/licenses/MIT).
