# Snapshot tests for the console output of the S3 print/summary methods.
# Constructed objects, fully deterministic.

fake_file_report <- function() {
  virustotal_file_report(list(
    data = list(
      id = "99017f6eebbac24f351415dd410d522d",
      type = "file",
      attributes = list(
        size = 68,
        sha256 = paste0(strrep("ab", 16), strrep("cd", 16)),
        last_analysis_stats = list(
          malicious = 2L, suspicious = 1L, undetected = 60L, harmless = 0L
        ),
        last_analysis_results = list(
          EngineA = list(category = "malicious"),
          EngineB = list(category = "malicious"),
          EngineC = list(category = "undetected")
        )
      )
    )
  ))
}

test_that("print.virustotal_file_report output is stable", {
  expect_snapshot(print(fake_file_report()))
})

test_that("print.virustotal_domain_report output is stable", {
  report <- virustotal_domain_report(list(
    data = list(
      id = "example.com",
      type = "domain",
      attributes = list(
        last_analysis_stats = list(
          malicious = 0L, suspicious = 0L, undetected = 25L, harmless = 68L
        ),
        categories = list(
          `Vendor A` = "search engines",
          `Vendor B` = "computers and internet"
        )
      )
    )
  ))
  expect_snapshot(print(report))
})

test_that("summary.virustotal_response lists malicious engines", {
  expect_snapshot(summary(fake_file_report()))
})

test_that("domain categories print the categories, not the vendor names", {
  # The API keys `categories` by vendor with the category as the value.
  # Printing names() reported "BitDefender, Sophos, ..." as the categories
  # of a domain every one of them called a search engine.
  report <- virustotal_domain_report(list(
    data = list(
      id = "example.com",
      type = "domain",
      attributes = list(categories = list(
        `Vendor A` = "search engines",
        `Vendor B` = "search engines",
        `Vendor C` = "computers and internet"
      ))
    )
  ))

  out <- paste(capture.output(print(report)), collapse = "\n")
  expect_match(out, "search engines")
  expect_match(out, "computers and internet")
  expect_false(grepl("Vendor A", out, fixed = TRUE))
  # Two vendors agreed; the category is worth saying once.
  expect_equal(lengths(regmatches(out, gregexpr("search engines", out))), 1L)
})

test_that("print.virustotal_error output is stable", {
  expect_snapshot({
    print(virustotal_error("Resource not found.", status_code = 404))
    print(virustotal_rate_limit_error("Rate limit exceeded.", retry_after = 37))
    print(virustotal_validation_error("Bad input.", parameter = "hash"))
  })
})
