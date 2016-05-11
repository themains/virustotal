## virustotal: R Client for the virustotal API

[![Build Status](https://travis-ci.org/soodoku/virustotal.svg?branch=master)](https://travis-ci.org/soodoku/virustotal)
[![Build status](https://ci.appveyor.com/api/projects/status/4aa0x74ggm51075o?svg=true)](https://ci.appveyor.com/project/soodoku/virustotal)
[![CRAN_Status_Badge](http://www.r-pkg.org/badges/version/virustotal)](http://cran.r-project.org/package=virustotal)
![](http://cranlogs.r-pkg.org/badges/grand-total/virustotal)

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

You can also launch vignettes within R:

```r
# Using virustotal
vignette("using_virustotal", package = "virustotal")
```
-----------------------------------
### License
Scripts are released under [MIT License](https://opensource.org/licenses/MIT).
