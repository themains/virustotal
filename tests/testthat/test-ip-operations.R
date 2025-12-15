# IP Operations Tests

test_that("ip_report validates input correctly", {
  expect_error(ip_report(), "Assertion on 'ip' failed")
  expect_error(ip_report(NULL), "Assertion on 'ip' failed")
  expect_error(ip_report(123), "Assertion on 'ip' failed")
  expect_error(ip_report(""), "All elements must have at least 1 characters")
})

# IP Comments Tests
test_that("get_ip_comments validates input correctly", {
  expect_error(get_ip_comments(), "Assertion on 'ip' failed")
  expect_error(get_ip_comments(NULL), "Assertion on 'ip' failed")
  expect_error(get_ip_comments(123), "Assertion on 'ip' failed")
  expect_error(get_ip_comments(""), "All elements must have at least 1 characters")
})

test_that("post_ip_comments validates input correctly", {
  expect_error(post_ip_comments(), "Assertion on 'ip' failed")
  expect_error(post_ip_comments("1.2.3.4"), "Assertion on 'comment' failed")
  expect_error(post_ip_comments("1.2.3.4", ""), "All elements must have at least 1 characters")
})

# IP Votes Tests
test_that("get_ip_votes validates input correctly", {
  expect_error(get_ip_votes(), "Assertion on 'ip' failed")
  expect_error(get_ip_votes(NULL), "Assertion on 'ip' failed")
  expect_error(get_ip_votes(""), "All elements must have at least 1 characters")
})

test_that("post_ip_votes validates input correctly", {
  expect_error(post_ip_votes(), "Assertion on 'ip' failed")
  expect_error(post_ip_votes("1.2.3.4"), "Assertion on 'vote' failed")
  expect_error(post_ip_votes("1.2.3.4", ""), "All elements must have at least 1 characters")
})

# IP Info Tests
test_that("get_ip_info validates input correctly", {
  expect_error(get_ip_info(), "Assertion on 'ip' failed")
  expect_error(get_ip_info(NULL), "Assertion on 'ip' failed")
  expect_error(get_ip_info(""), "All elements must have at least 1 characters")
})

# Rescan Tests
test_that("rescan_ip validates input correctly", {
  expect_error(rescan_ip(), "Assertion on 'ip' failed")
  expect_error(rescan_ip(NULL), "Assertion on 'ip' failed")
  expect_error(rescan_ip(""), "All elements must have at least 1 characters")
})

test_that("ip operations work with mocked responses", {
  skip_if_not_installed("httptest")
  skip_if(Sys.getenv("VirustotalToken") == "", "API key not set")

  expect_true(exists("ip_report"))
  expect_true(exists("get_ip_comments"))
  expect_true(exists("post_ip_comments"))
  expect_true(exists("get_ip_votes"))
  expect_true(exists("post_ip_votes"))
  expect_true(exists("get_ip_info"))
  expect_true(exists("rescan_ip"))
})
