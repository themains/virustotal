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
    set_key("  valid_32_character_api_key_1234567  "),
    "Removed leading/trailing whitespace"
  )
  expect_equal(
    Sys.getenv("VIRUSTOTAL_API_KEY"),
    "valid_32_character_api_key_1234567"
  )
  expect_equal(
    Sys.getenv("VirustotalToken"),
    "valid_32_character_api_key_1234567"
  )
})

test_that("set_key sets both environment variables", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = NA, VirustotalToken = NA))

  expect_message(
    result <- set_key("valid_32_character_api_key_1234567890"),
    "VirusTotal API key successfully set"
  )
  expect_true(result)
  expect_equal(
    Sys.getenv("VIRUSTOTAL_API_KEY"),
    "valid_32_character_api_key_1234567890"
  )
  expect_equal(
    Sys.getenv("VirustotalToken"),
    "valid_32_character_api_key_1234567890"
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
