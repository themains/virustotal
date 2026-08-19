test_that("request log initialization works", {
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

test_that("the request log tracks performed requests", {
  reset_rate_limit()

  record_request()
  status1 <- get_rate_limit_status()
  expect_equal(status1$requests_used, 1)
  expect_equal(status1$requests_remaining, 3)

  record_request()
  record_request()
  status2 <- get_rate_limit_status()
  expect_equal(status2$requests_used, 3)
  expect_equal(status2$requests_remaining, 1)
})

test_that("the status window slides correctly", {
  reset_rate_limit()

  current_time <- as.numeric(Sys.time())
  # Older than 60 seconds
  .virustotal_state$requests <- c(current_time - 70, current_time - 65)

  status <- get_rate_limit_status()
  expect_equal(status$requests_used, 0)
})

test_that("the request log handles NULL/empty states gracefully", {
  .virustotal_state$requests <- NULL
  .virustotal_state$max_requests <- NULL
  .virustotal_state$window_size <- NULL
  .virustotal_state$initialized <- NULL

  expect_no_error({
    status <- get_rate_limit_status()
    expect_equal(status$max_requests, 4)
    expect_equal(status$requests_used, 0)
  })

  expect_no_error(record_request())
  reset_rate_limit()
})

test_that("requests carry a throttle policy unless the option disables it", {
  req <- withr::with_options(
    list(virustotal.throttle = TRUE),
    vt_request("files/abc", key = "fake")
  )
  expect_false(is.null(req$policies$throttle))

  req <- withr::with_options(
    list(virustotal.throttle = FALSE),
    vt_request("files/abc", key = "fake")
  )
  expect_null(req$policies$throttle)
})

test_that("a base64url identifier survives URL assembly verbatim", {
  # req_url_path_append() must not escape or split the identifier; a mangled
  # character here addresses a nonexistent endpoint.
  id <- vt_url_id("https://shop.example.org/cart?sku=99&ref=abc")
  req <- vt_request(paste0("urls/", id), key = "fake")
  expect_equal(
    req$url,
    paste0("https://www.virustotal.com/api/v3/urls/", id)
  )
})

test_that("requests carry the retry policy, tunable by option", {
  # httr2's own suite covers that the retry loop honors 429/503 and
  # Retry-After. It cannot be replayed here: req_perform() returns a mocked
  # response through handle_resp() before it ever enters the retry loop, so
  # mocks exercise status handling (which is why the 429 test below works)
  # and never the backoff path. What is ours to verify is the wiring -- the
  # policy is present, reads the option, and caps the server's delay.
  req <- vt_request("files/abc", key = "fake")
  expect_false(is.null(req$policies$retry_max_tries))
  expect_equal(req$policies$retry_max_tries, 3)

  req <- withr::with_options(
    list(virustotal.max_tries = 5),
    vt_request("files/abc", key = "fake")
  )
  expect_equal(req$policies$retry_max_tries, 5)
})

test_that("a 429 response surfaces as a rate-limit error, not httr2's own", {
  httr2::local_mocked_responses(list(
    httr2::response(429, headers = list(`retry-after` = "7"))
  ))
  e <- tryCatch(
    virustotal_GET("files/abc", key = "fake"),
    error = function(e) e
  )
  expect_s3_class(e, "virustotal_rate_limit_error")
  expect_equal(e$retry_after, 7)
})

test_that("a mocked success flows through the full GET path", {
  httr2::local_mocked_responses(list(
    httr2::response(
      200,
      headers = list(`content-type` = "application/json"),
      body = charToRaw('{"data": {"id": "x"}}')
    )
  ))
  res <- virustotal_GET("files/abc", key = "fake")
  expect_equal(res$data$id, "x")
})

test_that("the status report honors a raised request-per-minute option", {
  # Reported "used 10/4, remaining -6" for any premium pace, because the
  # ceiling was frozen at init time instead of read at call time.
  withr::with_options(list(virustotal.requests_per_minute = 60), {
    reset_rate_limit()
    for (i in 1:10) record_request()
    status <- get_rate_limit_status()
    expect_equal(status$max_requests, 60)
    expect_equal(status$requests_used, 10)
    expect_equal(status$requests_remaining, 50)
  })
  reset_rate_limit()
})

test_that("a request that reached the API is logged even when it failed", {
  # A 404 or 429 spends quota; the usage log has to count it.
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  reset_rate_limit()
  httr2::local_mocked_responses(list(httr2::response(404)))
  expect_error(virustotal_GET("files/x"), class = "virustotal_error")
  expect_equal(get_rate_limit_status()$requests_used, 1)
  reset_rate_limit()
})

test_that("a server's Retry-After is capped, not obeyed blindly", {
  # Retry-After: 3600 would otherwise block the session for an hour.
  req <- vt_request("files/x", key = "fake")
  delay <- req$policies$retry_after(
    httr2::response(429, headers = list(`retry-after` = "3600"))
  )
  expect_equal(delay, 60)

  delay <- req$policies$retry_after(
    httr2::response(429, headers = list(`retry-after` = "5"))
  )
  expect_equal(delay, 5)
})
