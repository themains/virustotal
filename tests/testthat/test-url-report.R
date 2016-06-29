context("Verify data structures")

test_that("can decrypt secrets and data structures verified", {

    # Skips the test if doesn't have the key to open the secure vault
    skip_on_cran()

    token_file <- file("virustotal_api_key", "r")
    token <- suppressWarnings(readLines(token_file))
    close(token_file)
    
    set_key(token)

    report <- url_report("http://www.google.com")
  	expect_that(report, is_a("data.frame"))

  	Sys.sleep(10)

  	report <- ip_report(ip="8.8.8.8")
  	expect_that(report, is_a("list"))

  	Sys.sleep(10)

  	report <- rescan_file(hash='99017f6eebbac24f351415dd410d522d')
	expect_that(report, is_a("data.frame"))

	Sys.sleep(10)

	report <- scan_url("http://www.google.com")
	expect_that(report, is_a("data.frame"))

	Sys.sleep(10)

	report <- domain_report("http://www.google.com")
	expect_that(report, is_a("list"))

  })

