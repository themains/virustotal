context("Get url report")

test_that("can decrypt secrets", {
    # Skips the test if doesn't have the key to open the secure vault
    skip_when_missing_key("secure")

    # Decrypt a file stored in secure/inst/vault
    test <- decrypt("test", vault = "virustotal")
    set_key(test)
    report <- url_report("http://www.google.com")
  	expect_that(report, is_a("list"))
  })
