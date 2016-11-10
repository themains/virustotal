context("Verify data structures")

test_that("can decrypt secrets and data structures verified", {

  # Skips the test if doesn't have the key to open the secure vault
  skip_on_cran()

  token_file <- file("virustotal_api_key", "r")
  token <- suppressWarnings(readLines(token_file))
  close(token_file)
    
  set_key(token)

  # Testing URL Report
  # ------------------------------
  report <- url_report("http://www.google.com")
  expect_that(report, is_a("data.frame"))

  report <- url_report(scan_id = "ebdd15c397d2b0c6f50c3f2df531357d1201ff5976802316405e60880d6bf5ec-1478786749")
  expect_that(report, is_a("data.frame"))

  # Specify incorrect scan_id 
  report <- url_report(scan_id = "ebdd15c397d2b0c6f50c3f2df531357d1201ff59768786749")
  expect_that(report, is_a("data.frame"))
  # --------------------------------

  # Testing comments 
  # --------------------------------
  comments <- add_comments(hash='99017f6eebbac24f351415dd410d522d', comment="This is great.")
  expect_that(comments, is_a("data.frame"))

  # Testing file report 
  # ---------------------------
  fr <- file_report(hash='99017f6eebbac24f351415dd410d522d')
  expect_that(fr, is_a("data.frame"))

  # with incorrect hash 
  fr <- file_report(hash='99017f6eebbd')
  expect_that(fr, is_a("data.frame"))

  # Testing the rest (including rate_limiting)
  # ---------------------------------------------
  report <- ip_report(ip="8.8.8.8")
  expect_that(report, is_a("list"))

  report <- rescan_file(hash='99017f6eebbac24f351415dd410d522d')
	expect_that(report, is_a("data.frame"))

	report <- scan_url("http://www.google.com")
	expect_that(report, is_a("data.frame"))

	report <- domain_report("http://www.google.com")
	expect_that(report, is_a("list"))

  })

