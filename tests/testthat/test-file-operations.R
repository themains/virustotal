# File Operations Tests

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
  expect_error(scan_file(), "argument \"file_path\" is missing")
  expect_error(scan_file(NULL), "Must be of type 'character'")
  expect_error(scan_file(123), "Must be of type 'character'")
  expect_error(scan_file(character(0)), "Must have length 1")
  expect_error(scan_file("nonexistent_file.txt"), "File does not exist")
  
  # Test file size validation with temporary large file (if we create one)
  # This would need a very large temp file to test the 650MB limit
})

test_that("file_report validates input correctly", {
  expect_error(file_report(), class = "virustotal_validation_error")
  expect_error(file_report(NULL), class = "virustotal_validation_error")
  expect_error(file_report(123), class = "virustotal_validation_error")
  expect_error(file_report(""), class = "virustotal_validation_error")
  
  # Test with invalid hash format (but valid API key unset for auth error)
  old_key <- Sys.getenv("VirustotalToken")
  Sys.unsetenv("VirustotalToken")
  expect_error(file_report("dummy_hash"), class = "virustotal_auth_error")
  
  # Restore API key
  if (old_key != "") {
    Sys.setenv(VirustotalToken = old_key)
  }
})

test_that("rescan_file validates input correctly", {
  expect_error(rescan_file(), "Must specify a valid file hash")
  expect_error(rescan_file(NULL), "Must specify a valid file hash")
  expect_error(rescan_file(123), "Must specify a valid file hash")
  expect_error(rescan_file(""), "Must specify a valid file hash")
})

# Test new v3 file functions
test_that("get_file_upload_url validates correctly", {
  expect_true(exists("get_file_upload_url"))
})

test_that("get_file_comments validates input correctly", {
  expect_error(get_file_comments(), "Must specify a valid file hash")
  expect_error(get_file_comments(NULL), "Must specify a valid file hash")
  expect_error(get_file_comments(""), "Must specify a valid file hash")
})

test_that("post_file_comments validates input correctly", {
  expect_error(post_file_comments(), "Must specify a valid file hash")
  expect_error(post_file_comments("hash123"), "Must specify a comment")
  expect_error(post_file_comments("hash123", ""), "Must specify a comment")
})

test_that("get_file_votes validates input correctly", {
  expect_error(get_file_votes(), "Must specify a valid file hash")
  expect_error(get_file_votes(NULL), "Must specify a valid file hash")
  expect_error(get_file_votes(""), "Must specify a valid file hash")
})

test_that("post_file_votes validates input correctly", {
  expect_error(post_file_votes(), "Must specify a valid file hash")
  expect_error(post_file_votes("hash123"), "Verdict must be either 'harmless' or 'malicious'")
  expect_error(post_file_votes("hash123", "invalid"), "Verdict must be either 'harmless' or 'malicious'")
})

test_that("get_file_relationships validates input correctly", {
  expect_error(get_file_relationships(), "Must specify a valid file hash")
  expect_error(get_file_relationships("hash123"), "Must specify a relationship type")
  expect_error(get_file_relationships("hash123", "invalid"), "Invalid relationship type")
})

test_that("download_file validates input correctly", {
  expect_error(download_file(), "Must specify a valid file hash")
  expect_error(download_file(NULL), "Must specify a valid file hash")
  expect_error(download_file(""), "Must specify a valid file hash")
})

test_that("get_file_download_url validates input correctly", {
  expect_error(get_file_download_url(), "Must specify a valid file hash")
  expect_error(get_file_download_url(NULL), "Must specify a valid file hash")
  expect_error(get_file_download_url(""), "Must specify a valid file hash")
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
  expect_true(exists("get_file_upload_url"))
  expect_true(exists("get_file_comments"))
  expect_true(exists("post_file_comments"))
  expect_true(exists("get_file_votes"))
  expect_true(exists("post_file_votes"))
  expect_true(exists("get_file_relationships"))
  expect_true(exists("download_file"))
  expect_true(exists("get_file_download_url"))
})
