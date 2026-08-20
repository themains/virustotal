# Live smoke test against the real API. Off by default: run with
#   VT_INTEGRATION=true and a key in VIRUSTOTAL_API_KEY.

test_that("live integration smoke test", {
  skip_on_cran()
  skip_if(
    !identical(Sys.getenv("VT_INTEGRATION"), "true"),
    "Set VT_INTEGRATION=true to run against the live API"
  )
  skip_if(!has_vt_key(), "API key not set")

  # The suite-wide setup disables the throttle for mocked replays; a live
  # run must pace itself.
  withr::local_options(virustotal.throttle = TRUE)

  report <- domain_report("google.com")
  expect_s3_class(report, "virustotal_domain_report")
  expect_equal(report$data$id, "google.com")

  report <- ip_report("8.8.8.8")
  expect_type(report, "list")
  expect_equal(report$data$id, "8.8.8.8")

  report <- file_report("99017f6eebbac24f351415dd410d522d")
  expect_s3_class(report, "virustotal_file_report")

  expect_error(
    domain_report("no-such-domain-zzz-2f8a.invalid"),
    class = "virustotal_error"
  )
})
