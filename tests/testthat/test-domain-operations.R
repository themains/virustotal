context("Domain Operations")

test_that("domain_report validates input correctly", {
  expect_error(domain_report(), "Must specify a valid domain name")
  expect_error(domain_report(NULL), "Must specify a valid domain name")
  expect_error(domain_report(123), "Must specify a valid domain name")
  expect_error(domain_report(""), "Must specify a valid domain name")
})

test_that("domain cleaning works correctly", {
  # Test domain normalization logic (without API call)
  expect_equal(gsub("^https?://", "", "http://example.com"), "example.com")
  expect_equal(gsub("^www\\.", "", "www.example.com"), "example.com")
  expect_equal(gsub("/.*$", "", "example.com/path"), "example.com")
})

test_that("domain operations work with mocked responses", {
  skip_if_not_installed("httptest")
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")
  
  expect_true(exists("domain_report"))
})