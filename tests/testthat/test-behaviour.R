# Behaviour Tests

test_that("get_file_behaviour_summary validates input correctly", {
  expect_error(get_file_behaviour_summary(), "Assertion on 'hash' failed")
  expect_error(get_file_behaviour_summary(NULL), "Assertion on 'hash' failed")
  expect_error(get_file_behaviour_summary(123), "Assertion on 'hash' failed")
  expect_error(
    get_file_behaviour_summary(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_file_behaviour_mitre_trees validates input correctly", {
  expect_error(get_file_behaviour_mitre_trees(), "Assertion on 'hash' failed")
  expect_error(
    get_file_behaviour_mitre_trees(NULL),
    "Assertion on 'hash' failed"
  )
  expect_error(
    get_file_behaviour_mitre_trees(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_file_behaviours validates input correctly", {
  expect_error(get_file_behaviours(), "Assertion on 'hash' failed")
  expect_error(get_file_behaviours(NULL), "Assertion on 'hash' failed")
  expect_error(
    get_file_behaviours(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_behaviour_report validates input correctly", {
  expect_error(get_behaviour_report(), "Assertion on 'sandbox_id' failed")
  expect_error(get_behaviour_report(NULL), "Assertion on 'sandbox_id' failed")
  expect_error(
    get_behaviour_report(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_behaviour_html validates input correctly", {
  expect_error(get_behaviour_html(), "Assertion on 'sandbox_id' failed")
  expect_error(get_behaviour_html(NULL), "Assertion on 'sandbox_id' failed")
  expect_error(
    get_behaviour_html(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_behaviour_evtx validates input correctly", {
  expect_error(get_behaviour_evtx(), "Assertion on 'sandbox_id' failed")
  expect_error(get_behaviour_evtx(NULL), "Assertion on 'sandbox_id' failed")
  expect_error(
    get_behaviour_evtx(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_behaviour_pcap validates input correctly", {
  expect_error(get_behaviour_pcap(), "Assertion on 'sandbox_id' failed")
  expect_error(get_behaviour_pcap(NULL), "Assertion on 'sandbox_id' failed")
  expect_error(
    get_behaviour_pcap(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_behaviour_memdump validates input correctly", {
  expect_error(get_behaviour_memdump(), "Assertion on 'sandbox_id' failed")
  expect_error(get_behaviour_memdump(NULL), "Assertion on 'sandbox_id' failed")
  expect_error(
    get_behaviour_memdump(""),
    "All elements must have at least 1 characters"
  )
})

test_that("behaviour functions exist and are exported", {
  expect_true(exists("get_file_behaviour_summary"))
  expect_true(exists("get_file_behaviour_mitre_trees"))
  expect_true(exists("get_file_behaviours"))
  expect_true(exists("get_behaviour_report"))
  expect_true(exists("get_behaviour_html"))
  expect_true(exists("get_behaviour_evtx"))
  expect_true(exists("get_behaviour_pcap"))
  expect_true(exists("get_behaviour_memdump"))
})
