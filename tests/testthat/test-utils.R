test_that("format_file_size picks sensible units", {
  expect_equal(format_file_size(0), "0.00 B")
  expect_equal(format_file_size(1024), "1.00 KB")
  expect_equal(format_file_size(1536), "1.50 KB")
  expect_equal(format_file_size(1024^3), "1.00 GB")
})

test_that("validate_vt_response requires a data list", {
  expect_true(validate_vt_response(list(data = list(id = "x"))))
  expect_false(validate_vt_response(list()))
  expect_false(validate_vt_response("not a list"))
  expect_false(validate_vt_response(list(data = "scalar")))
})

test_that("temp dir helpers create and clean up", {
  d <- create_safe_temp_dir()
  expect_true(dir.exists(d))
  f <- file.path(d, "x.bin")
  writeBin(as.raw(1:4), f)
  expect_true(cleanup_temp_files(c(f, d)))
  expect_false(dir.exists(d))
})

test_that("virustotal_info prints without error", {
  expect_output(virustotal_info(), "VirusTotal R Package Information")
})
