test_that("set_key validates input correctly", {
  # Missing argument
  expect_error(set_key(), class = "virustotal_validation_error")
  
  # Wrong types
  expect_error(set_key(NULL), class = "virustotal_validation_error")
  expect_error(set_key(123), class = "virustotal_validation_error")
  expect_error(set_key(character(0)), class = "virustotal_validation_error")
  
  # Too short
  expect_error(set_key("short"), class = "virustotal_validation_error")
  
  # Common placeholder values
  expect_error(set_key("your_api_key_here"), class = "virustotal_validation_error")
  expect_error(set_key("api_key_here"), class = "virustotal_validation_error")
})

test_that("set_key handles whitespace correctly", {
  old_key <- Sys.getenv("VirustotalToken")
  
  # Test trimming whitespace
  expect_warning(
    set_key("  valid_32_character_api_key_1234567  "),
    "Removed leading/trailing whitespace"
  )
  expect_equal(Sys.getenv("VirustotalToken"), "valid_32_character_api_key_1234567")
  
  # Restore original key
  if (old_key != "") {
    Sys.setenv(VirustotalToken = old_key)
  } else {
    Sys.unsetenv("VirustotalToken")
  }
})

test_that("set_key sets environment variable correctly", {
  old_key <- Sys.getenv("VirustotalToken")
  
  expect_message(
    result <- set_key("valid_32_character_api_key_1234567890"),
    "VirusTotal API key successfully set"
  )
  expect_true(result)
  expect_equal(Sys.getenv("VirustotalToken"), "valid_32_character_api_key_1234567890")
  
  # Restore original key
  if (old_key != "") {
    Sys.setenv(VirustotalToken = old_key)
  } else {
    Sys.unsetenv("VirustotalToken")
  }
})

test_that("API functions require API key", {
  old_key <- Sys.getenv("VirustotalToken")
  Sys.unsetenv("VirustotalToken")
  
  expect_error(file_report("dummy_hash"), class = "virustotal_auth_error")
  expect_error(ip_report("8.8.8.8"), class = "virustotal_auth_error")
  expect_error(domain_report("example.com"), class = "virustotal_auth_error")
  
  # Restore original key
  if (old_key != "") {
    Sys.setenv(VirustotalToken = old_key)
  }
})
