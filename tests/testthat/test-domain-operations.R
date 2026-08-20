# Domain Operations Tests

test_that("domain_report validates input correctly", {
  expect_error(domain_report(), class = "virustotal_validation_error")
  expect_error(domain_report(NULL), class = "virustotal_validation_error")
  expect_error(domain_report(123), class = "virustotal_validation_error")
  expect_error(domain_report(""), class = "virustotal_validation_error")
  expect_error(
    domain_report("invalid..domain"),
    class = "virustotal_validation_error"
  )
})

test_that("domain_report strips a scheme before building the path", {
  # Was asserting base R's gsub() against literals, which would still pass if
  # domain_report() stopped cleaning domains altogether. Exercise the package.
  cap <- new_capture()
  use_capture(cap)

  domain_report("https://example.com")
  expect_equal(cap$last()$path, "domains/example.com")

  domain_report("http://example.com")
  expect_equal(cap$last()$path, "domains/example.com")
})

test_that("get_domain_comments validates input correctly", {
  expect_error(get_domain_comments(), "Assertion on 'domain' failed")
  expect_error(get_domain_comments(NULL), "Assertion on 'domain' failed")
  expect_error(get_domain_comments(123), "Assertion on 'domain' failed")
  expect_error(
    get_domain_comments(""),
    "All elements must have at least 1 characters"
  )
})

test_that("post_domain_comments validates input correctly", {
  expect_error(post_domain_comments(), "Assertion on 'domain' failed")
  expect_error(
    post_domain_comments("example.com"),
    "Assertion on 'comment' failed"
  )
  expect_error(
    post_domain_comments("example.com", ""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_domain_votes validates input correctly", {
  expect_error(get_domain_votes(), "Assertion on 'domain' failed")
  expect_error(get_domain_votes(NULL), "Assertion on 'domain' failed")
  expect_error(
    get_domain_votes(""),
    "All elements must have at least 1 characters"
  )
})

test_that("post_domain_votes validates input correctly", {
  expect_error(post_domain_votes(), "Assertion on 'domain' failed")
  expect_error(post_domain_votes("example.com"), "Assertion on 'vote' failed")
  expect_error(
    post_domain_votes("example.com", ""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_domain_info validates input correctly", {
  expect_error(get_domain_info(), "Assertion on 'domain' failed")
  expect_error(get_domain_info(NULL), "Assertion on 'domain' failed")
  expect_error(
    get_domain_info(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_domain_relationship validates input correctly", {
  expect_error(get_domain_relationship(), "Assertion on 'domain' failed")
  expect_error(get_domain_relationship(NULL), "Assertion on 'domain' failed")
  expect_error(
    get_domain_relationship(""),
    "All elements must have at least 1 characters"
  )
})

test_that("rescan_domain validates input correctly", {
  expect_error(rescan_domain(), "Assertion on 'domain' failed")
  expect_error(rescan_domain(NULL), "Assertion on 'domain' failed")
  expect_error(
    rescan_domain(""),
    "All elements must have at least 1 characters"
  )
})

test_that("domain endpoints request the documented v3 paths and bodies", {
  cap <- new_capture()
  use_capture(cap)

  domain_report("google.com")
  expect_equal(cap$last()$path, "domains/google.com")
  expect_equal(cap$last()$verb, "GET")

  get_domain_comments("google.com")
  expect_equal(cap$last()$path, "domains/google.com/comments")

  post_domain_comments("google.com", "a comment")
  expect_equal(cap$last()$path, "domains/google.com/comments")
  expect_equal(cap$last()$verb, "POST")
  expect_equal(cap$last()$body$data$type, "comment")
  expect_equal(cap$last()$body$data$attributes$text, "a comment")

  get_domain_votes("google.com")
  expect_equal(cap$last()$path, "domains/google.com/votes")

  post_domain_votes("google.com", "malicious")
  expect_equal(cap$last()$path, "domains/google.com/votes")
  expect_equal(cap$last()$body$data$type, "vote")
  expect_equal(cap$last()$body$data$attributes$verdict, "malicious")

  get_domain_relationship("google.com", "resolutions")
  expect_equal(cap$last()$path, "domains/google.com/relationships/resolutions")
})

test_that("domain_report wraps the response in its S3 class", {
  cap <- new_capture(response = list(
    data = list(
      id = "google.com",
      type = "domain",
      attributes = list(
        last_analysis_stats = list(
          malicious = 0L, suspicious = 0L, undetected = 20L, harmless = 70L
        )
      )
    )
  ))
  use_capture(cap)

  report <- domain_report("google.com")
  expect_s3_class(report, "virustotal_domain_report")
  expect_s3_class(report, "virustotal_response")
  expect_equal(report$data$id, "google.com")
})
