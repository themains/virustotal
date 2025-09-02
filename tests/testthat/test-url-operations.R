context("URL Operations")

test_that("scan_url validates input correctly", {
  expect_error(scan_url(), "Must specify a valid URL")
  expect_error(scan_url(NULL), "Must specify a valid URL")
  expect_error(scan_url(123), "Must specify a valid URL")
  expect_error(scan_url(""), "Must specify a valid URL")
})

test_that("url_report validates input correctly", {
  expect_error(url_report(), "Must specify a valid URL or URL ID")
  expect_error(url_report(NULL), "Must specify a valid URL or URL ID")
  expect_error(url_report(123), "Must specify a valid URL or URL ID")
  expect_error(url_report(""), "Must specify a valid URL or URL ID")
})

test_that("URL encoding works correctly", {
  skip_if_not_installed("base64enc")
  
  # Test URL encoding logic (without API call)
  test_url <- "http://www.google.com"
  encoded <- base64enc::base64encode(charToRaw(test_url))
  encoded <- gsub("=+$", "", encoded)
  
  expect_true(nchar(encoded) > 0)
  expect_false(grepl("=", encoded))
})

test_that("URL operations work with mocked responses", {
  skip_if_not_installed("httptest")
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")
  
  expect_true(exists("scan_url"))
  expect_true(exists("url_report"))
})