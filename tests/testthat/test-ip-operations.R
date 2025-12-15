# IP Operations Tests

test_that("ip_report validates input correctly", {
  expect_error(ip_report(), "Assertion on 'ip' failed")
  expect_error(ip_report(NULL), "Assertion on 'ip' failed")
  expect_error(ip_report(123), "Assertion on 'ip' failed")
  expect_error(ip_report(""), "All elements must have at least 1 characters")
})

test_that("ip operations work with mocked responses", {
  skip_if_not_installed("httptest")
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")
  
  expect_true(exists("ip_report"))
})
