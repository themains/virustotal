test_that("rate limiting initialization works", {
  # Reset state
  reset_rate_limit()
  
  status <- get_rate_limit_status()
  expect_equal(status$requests_used, 0)
  expect_equal(status$max_requests, 4)
  expect_equal(status$requests_remaining, 4)
})

test_that("rate limiting tracks requests", {
  # Reset state
  reset_rate_limit()
  
  # Make some requests
  rate_limit()
  status1 <- get_rate_limit_status()
  expect_equal(status1$requests_used, 1)
  expect_equal(status1$requests_remaining, 3)
  
  rate_limit()
  rate_limit()
  status2 <- get_rate_limit_status()
  expect_equal(status2$requests_used, 3)
  expect_equal(status2$requests_remaining, 1)
})

test_that("rate limiting enforces limits", {
  # Reset state
  reset_rate_limit()
  
  # Fill up the rate limit
  rate_limit()
  rate_limit()
  rate_limit()
  rate_limit()
  
  status <- get_rate_limit_status()
  expect_equal(status$requests_used, 4)
  expect_equal(status$requests_remaining, 0)
  
  # Next request should trigger waiting (we can't easily test the actual waiting)
  # Just verify the function doesn't error
  expect_silent(rate_limit())
})

test_that("rate limiting window slides correctly", {
  # Reset state
  reset_rate_limit()
  
  # Manually add old requests that should be expired
  current_time <- as.numeric(Sys.time())
  .virustotal_state$requests <- c(current_time - 70, current_time - 65)  # Older than 60 seconds
  
  # Check that old requests are cleaned
  status <- get_rate_limit_status()
  expect_equal(status$requests_used, 0)  # Old requests should be cleaned
})
