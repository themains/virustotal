context("Authentication")

test_that("set_key validates input correctly", {
  expect_error(set_key(), "Must specify API Key")
  expect_error(set_key(NULL), "Must specify API Key")
  expect_error(set_key(123), "Must specify API Key")
})

test_that("set_key sets environment variable", {
  old_key <- Sys.getenv("VirustotalToken")
  
  set_key("test_key_123")
  expect_equal(Sys.getenv("VirustotalToken"), "test_key_123")
  
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
  
  expect_error(file_report("dummy_hash"), "Please set application key")
  expect_error(ip_report("8.8.8.8"), "Please set application key")
  expect_error(domain_report("example.com"), "Please set application key")
  
  # Restore original key
  if (old_key != "") {
    Sys.setenv(VirustotalToken = old_key)
  }
})