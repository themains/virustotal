## virustotal: R Client for the Virustotal Public API

[![Build Status](https://travis-ci.org/soodoku/virustotal.svg?branch=master)](https://travis-ci.org/soodoku/virustotal)
[![Build status](https://ci.appveyor.com/api/projects/status/4aa0x74ggm51075o?svg=true)](https://ci.appveyor.com/project/soodoku/virustotal)
[![CRAN_Status_Badge](http://www.r-pkg.org/badges/version/virustotal)](http://cran.r-project.org/package=virustotal)
![](http://cranlogs.r-pkg.org/badges/grand-total/virustotal)

Use VirusTotal, a Google service that analyzes files and URLs for viruses, worms, trojans etc., provides category of the content hosted by a domain from a variety of prominent services, provides passive DNS information, among other things. See [http://www.virustotal.com](http://www.virustotal.com) for more information. 

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

To learn about how to use the package, read the [vignette](vignettes/using_virustotal.md). Or launch the vignette within R:

```r
# Using virustotal
vignette("using_virustotal", package = "virustotal")
```

### License
Scripts are released under the [MIT License](https://opensource.org/licenses/MIT).
