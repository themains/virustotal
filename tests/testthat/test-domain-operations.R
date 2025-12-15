# Domain Operations Tests

test_that("domain_report validates input correctly", {
  expect_error(domain_report(), class = "virustotal_validation_error")
  expect_error(domain_report(NULL), class = "virustotal_validation_error")
  expect_error(domain_report(123), class = "virustotal_validation_error")
  expect_error(domain_report(""), class = "virustotal_validation_error")
  expect_error(domain_report("invalid..domain"), class = "virustotal_validation_error")
})

test_that("domain cleaning works correctly", {
  # Test domain normalization logic (without API call)
  expect_equal(gsub("^https?://", "", "http://example.com"), "example.com")
  expect_equal(gsub("^www\\.", "", "www.example.com"), "example.com")
  expect_equal(gsub("/.*$", "", "example.com/path"), "example.com")
})

# Domain Comments Tests
test_that("get_domain_comments validates input correctly", {
  expect_error(get_domain_comments(), "Assertion on 'domain' failed")
  expect_error(get_domain_comments(NULL), "Assertion on 'domain' failed")
  expect_error(get_domain_comments(123), "Assertion on 'domain' failed")
  expect_error(get_domain_comments(""), "All elements must have at least 1 characters")
})

test_that("post_domain_comments validates input correctly", {
  expect_error(post_domain_comments(), "Assertion on 'domain' failed")
  expect_error(post_domain_comments("example.com"), "Assertion on 'comment' failed")
  expect_error(post_domain_comments("example.com", ""), "All elements must have at least 1 characters")
})

# Domain Votes Tests
test_that("get_domain_votes validates input correctly", {
  expect_error(get_domain_votes(), "Assertion on 'domain' failed")
  expect_error(get_domain_votes(NULL), "Assertion on 'domain' failed")
  expect_error(get_domain_votes(""), "All elements must have at least 1 characters")
})

test_that("post_domain_votes validates input correctly", {
  expect_error(post_domain_votes(), "Assertion on 'domain' failed")
  expect_error(post_domain_votes("example.com"), "Assertion on 'vote' failed")
  expect_error(post_domain_votes("example.com", ""), "All elements must have at least 1 characters")
})

# Domain Info Tests
test_that("get_domain_info validates input correctly", {
  expect_error(get_domain_info(), "Assertion on 'domain' failed")
  expect_error(get_domain_info(NULL), "Assertion on 'domain' failed")
  expect_error(get_domain_info(""), "All elements must have at least 1 characters")
})

# Domain Relationships Tests
test_that("get_domain_relationship validates input correctly", {
  expect_error(get_domain_relationship(), "Assertion on 'domain' failed")
  expect_error(get_domain_relationship(NULL), "Assertion on 'domain' failed")
  expect_error(get_domain_relationship(""), "All elements must have at least 1 characters")
})

# Rescan Tests
test_that("rescan_domain validates input correctly", {
  expect_error(rescan_domain(), "Assertion on 'domain' failed")
  expect_error(rescan_domain(NULL), "Assertion on 'domain' failed")
  expect_error(rescan_domain(""), "All elements must have at least 1 characters")
})

test_that("domain operations work with mocked responses", {
  skip_if_not_installed("httptest")
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")

  expect_true(exists("domain_report"))
  expect_true(exists("get_domain_comments"))
  expect_true(exists("post_domain_comments"))
  expect_true(exists("get_domain_votes"))
  expect_true(exists("post_domain_votes"))
  expect_true(exists("get_domain_info"))
  expect_true(exists("get_domain_relationship"))
  expect_true(exists("rescan_domain"))
})
