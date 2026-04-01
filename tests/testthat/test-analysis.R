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
