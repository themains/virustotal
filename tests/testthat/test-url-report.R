context("Get url report")

test_that("can decrypt secrets", {

    # Skips the test if doesn't have the key to open the secure vault
    skip_on_cran()

    token_file <- file("virustotal_api_key", "r")
    token <- suppressWarnings(readLines(token_file))

    set_key(token)
    report <- url_report("http://www.google.com")
  	expect_that(report, is_a("data.frame"))
  })

