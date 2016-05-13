---
title: "Using virustotal"
author: "Gaurav Sood"
date: "2016-05-13"
vignette: >
  %\VignetteIndexEntry{Using virustotal}
  %\VignetteEngine{knitr::rmarkdown}
  %\VignetteEncoding{UTF-8}
---

## Using virustotal

### Installation

To get the current development version from GitHub:



```r
#library("devtools")
install_github("soodoku/virustotal")
```

#### Load up the lib:


```r
library(virustotal)
```

```
## Error in library(virustotal): there is no package called 'virustotal'
```

#### Authentication

Start by getting the API key from [https://www.virustotal.com/](https://www.virustotal.com/). Next, set it:


```r
set_key("your_key")
```

#### Get domain report

Get report on a domain, including passive DNS:


```r
domain_report("http://www.google.com")
```

#### Get URL report

Get report on a domain, including URL:


```r
head(url_report("http://www.google.com"), 10)
```

#### Get IP report


```r
head(ip_report("8.8.8.8"), 10)
```
#### Get File Report


```r
head(file_report("99017f6eebbac24f351415dd410d522d"), 10)
```
