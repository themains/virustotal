# File Operations Tests

file_scan_response <- list(
  data = list(
    type = "analysis",
    id = "mock_analysis_id_123"
  )
)

file_report_response <- list(
  data = list(
    type = "file",
    id = "mock_file_id",
    attributes = list(
      last_analysis_results = list(
        "Antivirus1" = list(category = "undetected"),
        "Antivirus2" = list(category = "malicious")
      ),
      total_votes = list(
        harmless = 50,
        malicious = 2
      )
    )
  )
)

test_that("scan_file validates input correctly", {
  expect_error(scan_file(), "argument \"file_path\" is missing")
  expect_error(scan_file(NULL), "Must be of type 'character'")
  expect_error(scan_file(123), "Must be of type 'character'")
  expect_error(scan_file(character(0)), "Must have length 1")
  expect_error(scan_file("nonexistent_file.txt"), "File does not exist")
})

test_that("file_report validates input correctly", {
  expect_error(file_report(), class = "virustotal_validation_error")
  expect_error(file_report(NULL), class = "virustotal_validation_error")
  expect_error(file_report(123), class = "virustotal_validation_error")
  expect_error(file_report(""), class = "virustotal_validation_error")

  withr::local_envvar(c(VIRUSTOTAL_API_KEY = NA, VirustotalToken = NA))
  expect_error(file_report("dummy_hash"), class = "virustotal_auth_error")
})

test_that("rescan_file validates input correctly", {
  expect_error(rescan_file(), "Assertion on 'hash' failed")
  expect_error(rescan_file(NULL), "Assertion on 'hash' failed")
  expect_error(rescan_file(123), "Assertion on 'hash' failed")
  expect_error(
    rescan_file(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_file_comments validates input correctly", {
  expect_error(get_file_comments(), "Assertion on 'hash' failed")
  expect_error(get_file_comments(NULL), "Assertion on 'hash' failed")
  expect_error(
    get_file_comments(""),
    "All elements must have at least 1 characters"
  )
})

test_that("post_file_comments validates input correctly", {
  expect_error(post_file_comments(), "Assertion on 'hash' failed")
  expect_error(post_file_comments("hash123"), "Assertion on 'comment' failed")
  expect_error(
    post_file_comments("hash123", ""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_file_votes validates input correctly", {
  expect_error(get_file_votes(), "Assertion on 'hash' failed")
  expect_error(get_file_votes(NULL), "Assertion on 'hash' failed")
  expect_error(
    get_file_votes(""),
    "All elements must have at least 1 characters"
  )
})

test_that("post_file_votes validates input correctly", {
  expect_error(post_file_votes(), "Assertion on 'hash' failed")
  expect_error(post_file_votes("hash123"), "Assertion on 'verdict' failed")
  expect_error(
    post_file_votes("hash123", "invalid"),
    "Verdict must be either 'harmless' or 'malicious'"
  )
})

test_that("get_file_relationships validates input correctly", {
  expect_error(get_file_relationships(), "Assertion on 'hash' failed")
  expect_error(
    get_file_relationships("hash123"),
    "Assertion on 'relationship' failed"
  )
  expect_error(
    get_file_relationships("hash123", "invalid"),
    "Invalid relationship type"
  )
})

test_that("download_file validates input correctly", {
  expect_error(download_file(), "Assertion on 'hash' failed")
  expect_error(download_file(NULL), "Assertion on 'hash' failed")
  expect_error(
    download_file(""),
    "All elements must have at least 1 characters"
  )
})

test_that("get_file_download_url validates input correctly", {
  expect_error(get_file_download_url(), "Assertion on 'hash' failed")
  expect_error(get_file_download_url(NULL), "Assertion on 'hash' failed")
  expect_error(
    get_file_download_url(""),
    "All elements must have at least 1 characters"
  )
})

test_that("file endpoints request the documented v3 paths and bodies", {
  cap <- new_capture()
  use_capture(cap)
  hash <- "99017f6eebbac24f351415dd410d522d"

  file_report(hash)
  expect_equal(cap$last()$path, paste0("files/", hash))
  expect_equal(cap$last()$verb, "GET")

  get_file_upload_url()
  expect_equal(cap$last()$path, "files/upload_url")

  get_file_download_url(hash)
  expect_equal(cap$last()$path, paste0("files/", hash, "/download_url"))

  get_file_comments(hash)
  expect_equal(cap$last()$path, paste0("files/", hash, "/comments"))

  post_file_comments(hash, "a comment")
  expect_equal(cap$last()$path, paste0("files/", hash, "/comments"))
  expect_equal(cap$last()$body$data$type, "comment")

  get_file_votes(hash)
  expect_equal(cap$last()$path, paste0("files/", hash, "/votes"))

  post_file_votes(hash, "malicious")
  expect_equal(cap$last()$path, paste0("files/", hash, "/votes"))
  expect_equal(cap$last()$body$data$type, "vote")

  get_file_relationships(hash, "behaviours")
  expect_equal(
    cap$last()$path, paste0("files/", hash, "/relationships/behaviours")
  )
})

test_that("file_report wraps the response in its S3 class", {
  hash <- "99017f6eebbac24f351415dd410d522d"
  cap <- new_capture(response = list(
    data = list(
      id = hash,
      type = "file",
      attributes = list(
        size = 68,
        sha256 = strrep("ab", 32),
        last_analysis_stats = list(
          malicious = 61L, suspicious = 0L, undetected = 4L, harmless = 0L
        )
      )
    )
  ))
  use_capture(cap)

  report <- file_report(hash)
  expect_s3_class(report, "virustotal_file_report")
  expect_equal(report$data$attributes$last_analysis_stats$malicious, 61L)
})

test_that("download_file returns raw bytes or writes them to a path", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  payload <- as.raw(c(0x4d, 0x5a, 0x90, 0x00))
  httr2::local_mocked_responses(list(
    httr2::response(200, body = payload),
    httr2::response(200, body = payload)
  ))

  expect_identical(download_file("abc123"), payload)

  out <- tempfile()
  withr::defer(unlink(out))
  msg <- download_file("abc123", output_path = out)
  expect_match(msg, "File downloaded to:")
  expect_identical(readBin(out, "raw", n = 10), payload)
})

test_that("a failed download raises before anything reaches output_path", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  httr2::local_mocked_responses(list(httr2::response(404)))
  out <- tempfile()
  withr::defer(unlink(out))
  expect_error(download_file("abc123", output_path = out),
    class = "virustotal_error"
  )
  expect_false(file.exists(out))
})

test_that("behaviour artifact endpoints return raw bodies", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  payload <- charToRaw("<html></html>")
  httr2::local_mocked_responses(list(httr2::response(200, body = payload)))
  expect_identical(get_behaviour_html("id_sandbox"), payload)
})
