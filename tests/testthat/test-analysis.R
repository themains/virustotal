# Analysis Tests

test_that("get_analysis validates input correctly", {
  expect_error(get_analysis(), "Assertion on 'id' failed")
  expect_error(get_analysis(NULL), "Assertion on 'id' failed")
  expect_error(get_analysis(123), "Assertion on 'id' failed")
  expect_error(get_analysis(""), "All elements must have at least 1 characters")
})

test_that("get_analysis function exists and is exported", {
  expect_true(exists("get_analysis"))
})

test_that("scan and rescan analysis IDs can be polled with get_analysis", {
  cap <- new_capture(response = list(data = list(id = "u-fixture-123", type = "analysis")))
  use_capture(cap)
  hash <- strrep("a", 64)
  calls <- list(
    scan_url = "https://example.com", rescan_url = "https://example.com",
    rescan_file = hash, rescan_domain = "example.com", rescan_ip = "8.8.8.8"
  )
  for (fn in names(calls)) {
    submitted <- do.call(fn, list(calls[[fn]]))
    get_analysis(submitted$data$id)
    expect_equal(cap$last()$path, "analyses/u-fixture-123")
    expect_equal(cap$last()$verb, "GET")
  }
})
