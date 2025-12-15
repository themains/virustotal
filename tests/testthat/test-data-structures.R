# Integration Tests

test_that("integration tests with real API", {
  skip_on_cran()
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")
  
  # If API key file exists, use it
  if (file.exists("virustotal_api_key.enc")) {
    skip("Encrypted API key file requires special handling")
  }

  # Test basic functionality with known good inputs
  # These tests only run when API key is available
  
  # Test domain report (should return list)
  report <- domain_report("google.com")
  expect_type(report, "list")

  # Test IP report (should return list) 
  report <- ip_report("8.8.8.8")
  expect_type(report, "list")
  
  # Test file report with known hash (should return list)
  report <- file_report("99017f6eebbac24f351415dd410d522d")
  expect_type(report, "list")

})

