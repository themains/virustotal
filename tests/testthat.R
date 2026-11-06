# HTTPS fixtures use a private CA bundle, which requires OpenSSL on Windows.
if (.Platform$OS.type == "windows") {
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
}

library(testthat)
library(virustotal)

test_check("virustotal")
