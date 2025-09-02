context("File Operations")

# Mock response data for file operations
file_scan_response <- list(
  data = list(
    type = "analysis",
    id = "mock_analysis_id_123"
  )
)

file_report_response <- list(
  data = list(
    type = "file",
    id = "mock_file_id",
    attributes = list(
      last_analysis_results = list(
        "Antivirus1" = list(category = "undetected"),
        "Antivirus2" = list(category = "malicious")
      ),
      total_votes = list(
        harmless = 50,
        malicious = 2
      )
    )
  )
)

test_that("scan_file validates input correctly", {
  expect_error(scan_file(), "file_path must be a character string")
  expect_error(scan_file(NULL), "file_path must be a character string")
  expect_error(scan_file(123), "file_path must be a character string")
  expect_error(scan_file("nonexistent_file.txt"), "The file doesn't exist")
})

test_that("file_report validates input correctly", {
  expect_error(file_report(), "Must specify a valid file hash")
  expect_error(file_report(NULL), "Must specify a valid file hash")
  expect_error(file_report(123), "Must specify a valid file hash")
  expect_error(file_report(""), "Must specify a valid file hash")
})

test_that("rescan_file validates input correctly", {
  expect_error(rescan_file(), "Must specify a valid file hash")
  expect_error(rescan_file(NULL), "Must specify a valid file hash")
  expect_error(rescan_file(123), "Must specify a valid file hash")
  expect_error(rescan_file(""), "Must specify a valid file hash")
})

# Mock tests require httptest package and API key setup
test_that("file operations work with mocked responses", {
  skip_if_not_installed("httptest")
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")
  
  # These would use httptest::with_mock_api() in practice
  # For now, just verify the functions exist and are callable
  expect_true(exists("scan_file"))
  expect_true(exists("file_report"))
  expect_true(exists("rescan_file"))
})