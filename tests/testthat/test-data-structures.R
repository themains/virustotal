# Integration Tests

test_that("integration tests with real API", {
  skip_on_cran()
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")

  if (file.exists("virustotal_api_key.enc")) {
    skip("Encrypted API key file requires special handling")
  }

  report <- domain_report("google.com")
  expect_type(report, "list")

  report <- ip_report("8.8.8.8")
  expect_type(report, "list")

  report <- file_report("99017f6eebbac24f351415dd410d522d")
  expect_type(report, "list")
})
