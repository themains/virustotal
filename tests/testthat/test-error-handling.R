test_that("virustotal error classes work correctly", {
  err <- virustotal_error("Test message", status_code = 400)
  expect_s3_class(err, "virustotal_error")
  expect_equal(err$message, "Test message")
  expect_equal(err$status_code, 400)

  rate_err <- virustotal_rate_limit_error("Rate limit", retry_after = 60)
  expect_s3_class(rate_err, "virustotal_rate_limit_error")
  expect_s3_class(rate_err, "virustotal_error")
  expect_equal(rate_err$retry_after, 60)

  auth_err <- virustotal_auth_error("Auth failed")
  expect_s3_class(auth_err, "virustotal_auth_error")
  expect_s3_class(auth_err, "virustotal_error")

  val_err <- virustotal_validation_error(
    "Invalid param",
    parameter = "test",
    value = "bad"
  )
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
  expect_silent(virustotal_check(httr2::response(200)))

  expect_error(
    virustotal_check(httr2::response(401)),
    class = "virustotal_auth_error"
  )
  expect_error(
    virustotal_check(httr2::response(403)),
    class = "virustotal_auth_error"
  )
  expect_error(
    virustotal_check(httr2::response(404)),
    class = "virustotal_error"
  )
  expect_error(
    virustotal_check(httr2::response(500)),
    class = "virustotal_error"
  )
  expect_error(
    virustotal_check(httr2::response(204)),
    class = "virustotal_rate_limit_error"
  )
  expect_error(
    virustotal_check(httr2::response(429)),
    class = "virustotal_rate_limit_error"
  )
})

test_that("a 429 carries its Retry-After into the condition object", {
  e <- tryCatch(
    virustotal_check(
      httr2::response(429, headers = list(`retry-after` = "37"))
    ),
    error = function(e) e
  )
  expect_s3_class(e, "virustotal_rate_limit_error")
  expect_equal(e$retry_after, 37)
})

test_that("a transport failure surfaces as a virustotal_error", {
  # httr2 raises httr2_failure before any status handling, so without
  # re-raising it, tryCatch(virustotal_error = ) missed DNS failures,
  # refused connections and timeouts entirely.
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  local_mocked_bindings(
    vt_request = function(path, key = NULL) {
      httr2::request("https://127.0.0.1:9/api/v3") |>
        httr2::req_timeout(1) |>
        httr2::req_retry(max_tries = 1, retry_on_failure = FALSE)
    }
  )
  e <- tryCatch(virustotal_GET("files/x"), error = function(e) e)
  expect_s3_class(e, "virustotal_error")
  expect_match(conditionMessage(e), "Could not reach VirusTotal")
})

test_that("an empty or non-JSON 200 body becomes a virustotal_error", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))

  httr2::local_mocked_responses(list(httr2::response(200)))
  e <- tryCatch(virustotal_GET("files/x"), error = function(e) e)
  expect_s3_class(e, "virustotal_error")
  expect_match(conditionMessage(e), "empty response body")

  httr2::local_mocked_responses(list(
    httr2::response(200, body = charToRaw("<html>gateway</html>"))
  ))
  e <- tryCatch(virustotal_GET("files/x"), error = function(e) e)
  expect_s3_class(e, "virustotal_error")
  expect_match(conditionMessage(e), "not JSON")
})

test_that("ignored dots warn instead of vanishing", {
  # A typo -- get_file_comments(hash, cursors = "x") -- used to be dropped in
  # silence, leaving the caller paginating page one forever.
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  ok <- httr2::response(200, body = charToRaw('{"data": []}'))
  httr2::local_mocked_responses(list(ok, ok))
  expect_warning(virustotal_GET("files/x", cursors = "typo"), "Ignoring argument")
  expect_no_warning(virustotal_GET("files/x"))
})
