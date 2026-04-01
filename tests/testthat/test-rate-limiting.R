test_that("rate limiting initialization works", {
  reset_rate_limit()

  expect_true(.virustotal_state$initialized)
  expect_equal(.virustotal_state$max_requests, 4)
  expect_equal(.virustotal_state$window_size, 60)
  expect_length(.virustotal_state$requests, 0)

  status <- get_rate_limit_status()
  expect_equal(status$requests_used, 0)
  expect_equal(status$max_requests, 4)
  expect_equal(status$requests_remaining, 4)
})

test_that("rate limiting tracks requests", {
  reset_rate_limit()

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
  reset_rate_limit()

  rate_limit()
  rate_limit()
  rate_limit()
  rate_limit()

  status <- get_rate_limit_status()
  expect_equal(status$requests_used, 4)
  expect_equal(status$requests_remaining, 0)

  # Next request should trigger rate limit message
  expect_message(rate_limit(), "Rate limit reached")
})

test_that("rate limiting window slides correctly", {
  reset_rate_limit()

  current_time <- as.numeric(Sys.time())
  # Older than 60 seconds
  .virustotal_state$requests <- c(current_time - 70, current_time - 65)

  status <- get_rate_limit_status()
  expect_equal(status$requests_used, 0)
})

test_that("rate limiting handles NULL/empty states gracefully", {
  .virustotal_state$requests <- NULL
  .virustotal_state$max_requests <- NULL
  .virustotal_state$window_size <- NULL
  .virustotal_state$initialized <- NULL

  expect_no_error({
    status <- get_rate_limit_status()
    expect_equal(status$max_requests, 4)
    expect_equal(status$requests_used, 0)
  })

  expect_no_error(rate_limit())
})
