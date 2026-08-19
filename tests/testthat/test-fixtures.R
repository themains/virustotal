# Replay tests against recorded API responses.
#
# The fixtures under _fixtures/ were recorded once against the live v3 API
# with httptest2::with_mock_dir(). They contain response bodies only --
# httptest2 does not write request headers, so the x-apikey never lands on
# disk; tests/testthat/helper-fixtures.R asserts that on every run.
#
# To re-record after an API change: delete the directory, set
# VIRUSTOTAL_API_KEY, and run this file.

skip_if_not_installed("httptest2")
# Not shipped in the tarball (see .Rbuildignore): the recorded paths are
# longer than a tarball can portably store.
skip_if_not(dir.exists("_fixtures"), "Fixtures not present in this build")

test_that("a domain report parses into its class from a recorded response", {
  local_key_for_replay()
  httptest2::with_mock_dir("_fixtures/domain", {
    report <- domain_report("google.com")

    expect_s3_class(report, "virustotal_domain_report")
    expect_equal(report$data$id, "google.com")
    expect_equal(report$data$type, "domain")

    stats <- report$data$attributes$last_analysis_stats
    expect_type(stats$malicious, "integer")
    expect_true(stats$harmless > 0)
    expect_type(report$data$attributes$categories, "list")
  })
})

test_that("a file report parses into its class from a recorded response", {
  local_key_for_replay()
  httptest2::with_mock_dir("_fixtures/file", {
    report <- file_report("99017f6eebbac24f351415dd410d522d")

    expect_s3_class(report, "virustotal_file_report")
    expect_equal(nchar(report$data$attributes$sha256), 64)
    expect_true(report$data$attributes$last_analysis_stats$malicious > 0)
    expect_type(report$data$attributes$last_analysis_results, "list")
  })
})

test_that("an IP report parses from a recorded response", {
  local_key_for_replay()
  httptest2::with_mock_dir("_fixtures/ip", {
    report <- ip_report("8.8.8.8")

    expect_equal(report$data$id, "8.8.8.8")
    expect_equal(report$data$attributes$country, "US")
    expect_type(report$data$attributes$asn, "integer")
  })
})

test_that("a URL report resolves its base64 identifier against the API", {
  local_key_for_replay()
  # The identifier this package computes locally is the one the API
  # answers to -- the round trip no unit test can prove on its own.
  httptest2::with_mock_dir("_fixtures/url", {
    report <- url_report("http://www.google.com")

    expect_type(report$data$id, "character")
    expect_true(report$data$attributes$last_analysis_stats$harmless > 0)
  })
})

test_that("comments come back as a list of comment objects", {
  local_key_for_replay()
  httptest2::with_mock_dir("_fixtures/comments", {
    res <- get_domain_comments("google.com")
    expect_type(res$data, "list")
  })
})

test_that("an unknown resource raises a typed not-found error", {
  local_key_for_replay()
  httptest2::with_mock_dir("_fixtures/notfound", {
    expect_error(
      file_report("0123456789abcdef0123456789abcdef"),
      class = "virustotal_error"
    )
  })
})
