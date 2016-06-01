---
title: "Using virustotal"
author: "Gaurav Sood"
date: "2016-06-01"
vignette: >
  %\VignetteIndexEntry{Using virustotal}
  %\VignetteEngine{knitr::rmarkdown}
  %\VignetteEncoding{UTF-8}
---

## Using virustotal

### Installation

To get the current development version from GitHub:


```r
#library(devtools)
install_github("soodoku/virustotal")
```

#### Load up the lib:


```r
library(virustotal)
```

#### Authentication

Start by getting the API key from [https://www.virustotal.com/](https://www.virustotal.com/). Next, set it:


```r
set_key("your_key")
```

#### Get domain report

Get report on a domain, including passive DNS:


```r
domain_report("http://www.google.com")$categories
```
```
## [[1]]
## [1] "searchengines"
```
#### Scan URL 


```r
scan_url("http://www.google.com")
```

```
##                                                                                                             permalink               resource
## 1 https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/analysis/1464817664/ http://www.google.com/
```

#### Get URL report

Get report on a domain, including URL:


```r
head(url_report("http://www.google.com")[, 1:2], 10)
```
```
##                                                                        scan_id              resource
## 1  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 2  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 3  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 4  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 5  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 6  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 7  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 8  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 9  dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
## 10 dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1464816996 http://www.google.com
```
#### Get IP report


```r
ip_report("8.8.8.8")$country
```
```
## [1] "US"
```

#### Get File Report


```r
head(file_report("99017f6eebbac24f351415dd410d522d")[,1:2], 10)
```

```
                                                                    scans                                                                     scan_id
## Bkav                                           FALSE, 1.3.0.8042, 20160601 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## TotalDefense               TRUE, 37.1.62.1, Win32/ASuspect.HDBBD, 20160601 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## MicroWorld-eScan  TRUE, 12.0.250.0, Generic.Malware.V!w.7232B058, 20160601 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## nProtect         TRUE, 2016-06-01.01, Trojan/W32.Small.28672.BJA, 20160601 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## CMC                           TRUE, 1.1.0.977, Trojan.Win32.VB!O, 20160530 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## CAT-QuickHeal                      TRUE, 14.00, Trojan.Comame.r3, 20160601 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## ALYac                TRUE, 1.0.1.9, Generic.Malware.V!w.7232B058, 20160601 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## Malwarebytes                      TRUE, 2.1.1.1115, Trojan.Qhost, 20160601 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## Zillya                   TRUE, 2.0.0.2901, Trojan.VB.Win32.33493, 20160531 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
## SUPERAntiSpyware                               FALSE, 5.6.0.1032, 20160601 52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1464797947
```

#### Scan File 


```r
scan_file("using_virustotal.Rmd")[,1:2]
```
```
##                                                                      scan_id                                     sha1
## 1 a9e60cd4d1e3ea00a78f7e92b77f250b26297d79e387e30916de3973a03b28a0-1464822937 303e723fd79416c3a8f3ac8247f82ed2f22e635d
```

#### Rescan File


```r
rescan_file(hash='99017f6eebbac24f351415dd410d522d')[,1:2]
```

```
##                                                                                                               permalink response_code
## 1 https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1464817836/             1
```

