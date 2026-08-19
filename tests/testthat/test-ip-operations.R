# IP Operations Tests

test_that("ip_report validates input correctly", {
  expect_error(ip_report(), "Assertion on 'ip' failed")
  expect_error(ip_report(NULL), "Assertion on 'ip' failed")
  expect_error(ip_report(123), "Assertion on 'ip' failed")
  expect_error(
    ip_report(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_ip_comments validates input correctly", {
  expect_error(get_ip_comments(), "Assertion on 'ip' failed")
  expect_error(get_ip_comments(NULL), "Assertion on 'ip' failed")
  expect_error(get_ip_comments(123), "Assertion on 'ip' failed")
  expect_error(
    get_ip_comments(""),
    "All elements must have at least 1 characters"
  )
})

test_that("post_ip_comments validates input correctly", {
  expect_error(post_ip_comments(), "Assertion on 'ip' failed")
  expect_error(post_ip_comments("1.2.3.4"), "Assertion on 'comment' failed")
  expect_error(
    post_ip_comments("1.2.3.4", ""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_ip_votes validates input correctly", {
  expect_error(get_ip_votes(), "Assertion on 'ip' failed")
  expect_error(get_ip_votes(NULL), "Assertion on 'ip' failed")
  expect_error(
    get_ip_votes(""),
    "All elements must have at least 1 characters"
  )
})

test_that("post_ip_votes validates input correctly", {
  expect_error(post_ip_votes(), "Assertion on 'ip' failed")
  expect_error(post_ip_votes("1.2.3.4"), "Assertion on 'vote' failed")
  expect_error(
    post_ip_votes("1.2.3.4", ""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_ip_info validates input correctly", {
  expect_error(get_ip_info(), "Assertion on 'ip' failed")
  expect_error(get_ip_info(NULL), "Assertion on 'ip' failed")
  expect_error(
    get_ip_info(""),
    "All elements must have at least 1 characters"
  )
})

test_that("rescan_ip validates input correctly", {
  expect_error(rescan_ip(), "Assertion on 'ip' failed")
  expect_error(rescan_ip(NULL), "Assertion on 'ip' failed")
  expect_error(
    rescan_ip(""),
    "All elements must have at least 1 characters"
  )
})

test_that("ip endpoints request the documented v3 paths and bodies", {
  cap <- new_capture()
  use_capture(cap)

  ip_report("8.8.8.8")
  expect_equal(cap$last()$path, "ip_addresses/8.8.8.8")
  expect_equal(cap$last()$verb, "GET")

  get_ip_comments("8.8.8.8")
  expect_equal(cap$last()$path, "ip_addresses/8.8.8.8/comments")

  post_ip_comments("8.8.8.8", "a comment")
  expect_equal(cap$last()$path, "ip_addresses/8.8.8.8/comments")
  expect_equal(cap$last()$body$data$type, "comment")

  get_ip_votes("8.8.8.8")
  expect_equal(cap$last()$path, "ip_addresses/8.8.8.8/votes")

  post_ip_votes("8.8.8.8", "harmless")
  expect_equal(cap$last()$path, "ip_addresses/8.8.8.8/votes")
  expect_equal(cap$last()$body$data$type, "vote")
  expect_equal(cap$last()$body$data$attributes$verdict, "harmless")
})
