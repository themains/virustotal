## virustotal: R Client for the VirusTotal Public API 2.0

[![Build Status](https://travis-ci.org/themains/virustotal.svg?branch=master)](https://travis-ci.org/themains/virustotal)
[![Build status](https://ci.appveyor.com/api/projects/status/5o45rcviuuxtobo7?svg=true)](https://ci.appveyor.com/project/soodoku/virustotal-6owbf)
[![CRAN_Status_Badge](https://www.r-pkg.org/badges/version/virustotal)](https://cran.r-project.org/package=virustotal)
![](https://cranlogs.r-pkg.org/badges/grand-total/virustotal)
[![codecov](https://codecov.io/gh/themains/virustotal/branch/master/graph/badge.svg)](https://app.codecov.io/gh/themains/virustotal)


Use [VirusTotal](http://www.virustotal.com), a Google service that analyzes files and URLs for viruses, worms, trojans etc., provides category of the content hosted by a domain from a variety of prominent services, provides passive DNS information, among other things. 

As of June, 2016, Public API 2.0 had the following rate limits:

|  Unit of time | Rate Limit            |
| ------------- | --------------------- |
| Minute        | 4 requests/minute     |
| Day           | 5760 requests/day     |
| Month         | 178560 requests/month |

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

To learn about how to use the package, read the [vignette](vignettes/using_virustotal.md). Or launch the vignette within R:

```r
# Using virustotal
vignette("using_virustotal", package = "virustotal")
```

### License
Scripts are released under the [MIT License](https://opensource.org/licenses/MIT).
