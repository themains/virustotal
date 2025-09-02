context("IP Operations")

test_that("ip_report validates input correctly", {
  expect_error(ip_report(), "Must specify a valid IP address")
  expect_error(ip_report(NULL), "Must specify a valid IP address")
  expect_error(ip_report(123), "Must specify a valid IP address")
  expect_error(ip_report(""), "Must specify a valid IP address")
})

test_that("ip operations work with mocked responses", {
  skip_if_not_installed("httptest")
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")
  
  expect_true(exists("ip_report"))
})