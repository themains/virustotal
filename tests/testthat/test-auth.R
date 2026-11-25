test_that("set_key validates input correctly", {
  expect_error(set_key(), class = "virustotal_validation_error")

  expect_error(set_key(NULL), class = "virustotal_validation_error")
  expect_error(set_key(123), class = "virustotal_validation_error")
  expect_error(set_key(character(0)), class = "virustotal_validation_error")

  expect_error(set_key("short"), class = "virustotal_validation_error")

  expect_error(
    set_key("your_api_key_here"),
    class = "virustotal_validation_error"
  )
  expect_error(
    set_key("api_key_here"),
    class = "virustotal_validation_error"
  )
})

test_that("set_key handles whitespace correctly", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = NA, VirustotalToken = NA))

  expect_warning(
    set_key("  abcdefghijklmnopqrstuvwxyz1234567  "),
    "Removed leading/trailing whitespace"
  )
  expect_equal(
    Sys.getenv("VIRUSTOTAL_API_KEY"),
    "abcdefghijklmnopqrstuvwxyz1234567"
  )
  expect_equal(
    Sys.getenv("VirustotalToken"),
    "abcdefghijklmnopqrstuvwxyz1234567"
  )
})

test_that("set_key sets both environment variables", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = NA, VirustotalToken = NA))

  expect_message(
    result <- set_key("abcdefghijklmnopqrstuvwxyz1234567890"),
    "VirusTotal API key successfully set"
  )
  expect_true(result)
  expect_equal(
    Sys.getenv("VIRUSTOTAL_API_KEY"),
    "abcdefghijklmnopqrstuvwxyz1234567890"
  )
  expect_equal(
    Sys.getenv("VirustotalToken"),
    "abcdefghijklmnopqrstuvwxyz1234567890"
  )
})

test_that("VIRUSTOTAL_API_KEY alone is honored, and wins over the old name", {
  withr::local_envvar(c(
    VIRUSTOTAL_API_KEY = "canonical_32_character_key_123456",
    VirustotalToken = NA
  ))
  expect_identical(vt_key(), "canonical_32_character_key_123456")

  withr::local_envvar(c(VirustotalToken = "legacy_32_character_key_123456789"))
  expect_identical(vt_key(), "canonical_32_character_key_123456")
})

test_that("API functions require API key", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = NA, VirustotalToken = NA))

  expect_error(file_report("dummy_hash"), class = "virustotal_auth_error")
  expect_error(ip_report("8.8.8.8"), class = "virustotal_auth_error")
  expect_error(domain_report("example.com"), class = "virustotal_auth_error")
})

test_that("vt_key errors as a typed condition when nothing is set", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = NA, VirustotalToken = NA))
  expect_error(vt_key(), class = "virustotal_auth_error")
  expect_false(has_vt_key())
})

test_that("an invalid replacement key leaves the configured key intact", {
  key <- strrep("a", 64)
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = key, VirustotalToken = key))
  for (invalid in c(strrep(" ", 64), paste0(strrep(" ", 32), "short"))) {
    expect_error(set_key(invalid), class = "virustotal_validation_error")
    expect_identical(Sys.getenv("VIRUSTOTAL_API_KEY"), key)
    expect_identical(Sys.getenv("VirustotalToken"), key)
  }
})

test_that("single-object lookups honor a key supplied for one request", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = NA, VirustotalToken = NA))
  key <- strrep("a", 64)
  httr2::local_mocked_responses(function(req) {
    headers <- httr2::req_get_headers(req, redacted = "reveal")
    expect_identical(headers[["x-apikey"]], key)
    httr2::response(200, body = charToRaw('{"data":{}}'))
  })
  expect_no_error(get_domain_info("example.com", key = key))
  expect_no_error(get_ip_info("8.8.8.8", key = key))
})
