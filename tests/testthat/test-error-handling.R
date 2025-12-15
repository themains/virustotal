test_that("virustotal error classes work correctly", {
  # Test basic error
  err <- virustotal_error("Test message", status_code = 400)
  expect_s3_class(err, "virustotal_error")
  expect_equal(err$message, "Test message")
  expect_equal(err$status_code, 400)
  
  # Test rate limit error
  rate_err <- virustotal_rate_limit_error("Rate limit", retry_after = 60)
  expect_s3_class(rate_err, "virustotal_rate_limit_error")
  expect_s3_class(rate_err, "virustotal_error")
  expect_equal(rate_err$retry_after, 60)
  
  # Test auth error
  auth_err <- virustotal_auth_error("Auth failed")
  expect_s3_class(auth_err, "virustotal_auth_error")
  expect_s3_class(auth_err, "virustotal_error")
  
  # Test validation error
  val_err <- virustotal_validation_error("Invalid param", parameter = "test", value = "bad")
  expect_s3_class(val_err, "virustotal_validation_error")
  expect_s3_class(val_err, "virustotal_error")
  expect_equal(val_err$parameter, "test")
  expect_equal(val_err$value, "bad")
})

test_that("error printing works", {
  err <- virustotal_error("Test error", status_code = 404)
  output <- capture.output(print(err))
  expect_true(grepl("VirusTotal API Error: Test error", output[1]))
  expect_true(grepl("HTTP Status Code: 404", output[2]))
})

test_that("virustotal_check handles HTTP status codes", {
  # Test success - should not error
  success_resp <- list(status_code = 200)
  expect_silent(virustotal_check(success_resp))
  
  # Test auth error  
  auth_resp <- list(status_code = 401)
  expect_error(virustotal_check(auth_resp), class = "virustotal_auth_error")
  
  # Test not found
  not_found_resp <- list(status_code = 404)
  expect_error(virustotal_check(not_found_resp), class = "virustotal_error")
  
  # Test server error
  server_error_resp <- list(status_code = 500)
  expect_error(virustotal_check(server_error_resp), class = "virustotal_error")
  
  # Test rate limit - simple case (will use default retry_after = 60)
  # We don't need to mock httr::headers, just test the basic error flow
  rate_limit_resp <- list(status_code = 204)
  expect_error(virustotal_check(rate_limit_resp), class = "virustotal_rate_limit_error")
})

