# URL Operations Tests

test_that("scan_url validates input correctly", {
  expect_error(scan_url(), "Assertion on 'url' failed")
  expect_error(scan_url(NULL), "Assertion on 'url' failed")
  expect_error(scan_url(123), "Assertion on 'url' failed")
  expect_error(
    scan_url(""),
    "All elements must have at least 1 characters"
  )
})

test_that("url_report validates input correctly", {
  expect_error(url_report(), "Assertion on 'url_id' failed")
  expect_error(url_report(NULL), "Assertion on 'url_id' failed")
  expect_error(url_report(123), "Assertion on 'url_id' failed")
  expect_error(
    url_report(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_url_comments validates input correctly", {
  expect_error(get_url_comments(), "Assertion on 'url_id' failed")
  expect_error(get_url_comments(NULL), "Assertion on 'url_id' failed")
  expect_error(get_url_comments(123), "Assertion on 'url_id' failed")
  expect_error(
    get_url_comments(""),
    "All elements must have at least 1 characters"
  )
})

test_that("post_url_comments validates input correctly", {
  expect_error(post_url_comments(), "Assertion on 'url_id' failed")
  expect_error(post_url_comments("validurl"), "Assertion on 'comment' failed")
  expect_error(
    post_url_comments("validurl", ""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_url_votes validates input correctly", {
  expect_error(get_url_votes(), "Assertion on 'url_id' failed")
  expect_error(get_url_votes(NULL), "Assertion on 'url_id' failed")
  expect_error(
    get_url_votes(""),
    "All elements must have at least 1 characters"
  )
})

test_that("post_url_votes validates input correctly", {
  expect_error(post_url_votes(), "Assertion on 'url_id' failed")
  expect_error(
    post_url_votes("validurl"),
    "Verdict must be either 'harmless' or 'malicious'"
  )
  expect_error(
    post_url_votes("validurl", "invalid"),
    "Verdict must be either 'harmless' or 'malicious'"
  )
})

test_that("get_url_relationships validates input correctly", {
  expect_error(get_url_relationships(), "Assertion on 'url_id' failed")
  expect_error(
    get_url_relationships("validurl"),
    "Assertion on 'relationship' failed"
  )
  expect_error(
    get_url_relationships("validurl", ""),
    "All elements must have at least 1 characters"
  )
})

test_that("rescan_url validates input correctly", {
  expect_error(rescan_url(), "Assertion on 'url_id' failed")
  expect_error(rescan_url(NULL), "Assertion on 'url_id' failed")
  expect_error(
    rescan_url(""),
    "All elements must have at least 1 characters"
  )
})

test_that("vt_url_id matches the documented identifier for a known URL", {
  # Fixed vocabulary from the v3 API docs: the identifier of
  # http://www.google.com is its unpadded URL-safe base64 encoding.
  expect_identical(
    vt_url_id("http://www.google.com"),
    "aHR0cDovL3d3dy5nb29nbGUuY29t"
  )
  expect_false(grepl("[=+/]", vt_url_id("https://example.org/a?b=c&d=e")))
})

test_that("URL operations work with mocked responses", {
  skip_if_not_installed("httptest")
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")

  expect_true(exists("scan_url"))
  expect_true(exists("url_report"))
})
