## virustotal: R Client for the virustotal API

[![Build Status](https://travis-ci.org/soodoku/virustotal.svg?branch=master)](https://travis-ci.org/soodoku/virustotal)
[![Build status](https://ci.appveyor.com/api/projects/status/4aa0x74ggm51075o?svg=true)](https://ci.appveyor.com/project/soodoku/virustotal)
[![CRAN_Status_Badge](http://www.r-pkg.org/badges/version/virustotal)](http://cran.r-project.org/package=virustotal)
![](http://cranlogs.r-pkg.org/badges/grand-total/virustotal)

Access VirusTotal, a Google service that analyzes files and URLs for viruses, worms, trojans etc. and also provides category of the content hosted by domain via websense (need a private API key for that). 

### Installation

To get the current released version from CRAN:
```r
install.packages("virustotal")
```

To get the current development version from GitHub:

```r
install.packages("devtools")
devtools::install_github("soodoku/virustotal", build_vignettes = TRUE)
```

Read a [vignette](vignettes/using_virustotal.md) about how to use virustotal. Or launch the vignette within R:

```r
# Using virustotal
vignette("using_virustotal", package = "virustotal")
```

### License
Scripts are released under [MIT License](https://opensource.org/licenses/MIT).
