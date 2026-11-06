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

test_that("sandbox IDs use escaped paths for reports and binary artifacts", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  id <- paste0(strrep("a", 64), "_VirusTotal Jujubox")
  seen <- character()
  httr2::local_mocked_responses(function(req) {
    seen <<- c(seen, req$url)
    httr2::response(200, body = charToRaw('{"data":{"id":"fixture"}}'))
  })
  get_behaviour_report(id)
  for (suffix in c("html", "evtx", "pcap", "memdump")) {
    do.call(paste0("get_behaviour_", suffix), list(id))
  }
  base <- paste0("https://www.virustotal.com/api/v3/file_behaviours/",
                 strrep("a", 64), "_VirusTotal%20Jujubox")
  expect_equal(seen, c(base, paste0(base, "/", c("html", "evtx", "pcap", "memdump"))))
})

test_that("path encoding preserves IPv6 and escapes literal reserved characters", {
  expect_equal(vt_request("ip_addresses/2001:db8::1", key = "fake")$url,
               "https://www.virustotal.com/api/v3/ip_addresses/2001:db8::1")
  expect_equal(vt_request("file_behaviours/id_%?#\u00e9", key = "fake")$url,
               "https://www.virustotal.com/api/v3/file_behaviours/id_%25%3F%23%C3%A9")
})
