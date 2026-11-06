local_sized_file <- function(size, env = parent.frame()) {
  f <- withr::local_tempfile(.local_envir = env)
  con <- file(f, "wb")
  writeBin(as.raw(c(0, 10, 127, 255)), con)
  seek(con, size - 1)
  writeBin(as.raw(0), con)
  close(con)
  f
}

test_that("file uploads choose the correct endpoint at size boundaries", {
  f <- withr::local_tempfile()
  writeBin(as.raw(c(0, 1, 127, 255)), f)
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  upload_url <- "https://www.virustotal.com/_ah/upload/one-use?token=a%2Fb"
  for (size in c(32 * 1024^2 - 1, 32 * 1024^2, 32 * 1024^2 + 1, 650 * 1024^2)) {
    f <- local_sized_file(size)
    calls <- list()
    httr2::local_mocked_responses(function(req) {
      calls[[length(calls) + 1L]] <<- req
      body <- if (endsWith(req$url, "/files/upload_url")) {
        jsonlite::toJSON(list(data = upload_url), auto_unbox = TRUE)
      } else {
        '{"data":{"type":"analysis","id":"fixture-analysis"}}'
      }
      httr2::response(200, body = charToRaw(body))
    })
    result <- scan_file(f)
    expect_s3_class(result, "virustotal_file_scan")
    expect_equal(result$data$id, "fixture-analysis")
    if (size <= 32 * 1024^2) {
      expect_length(calls, 1)
      expect_equal(calls[[1]]$url, "https://www.virustotal.com/api/v3/files")
    } else {
      expect_length(calls, 2)
      expect_equal(calls[[1]]$url, "https://www.virustotal.com/api/v3/files/upload_url")
      expect_equal(calls[[2]]$url, upload_url)
      expect_equal(calls[[2]]$policies$retry_max_tries, 1)
    }
    expect_equal(tail(calls, 1)[[1]]$body$type, "multipart")
  }
})

test_that("oversized files are rejected without an HTTP request", {
  f <- withr::local_tempfile()
  writeBin(as.raw(0), f)
  f <- local_sized_file(650 * 1024^2 + 1)
  httr2::local_mocked_responses(function(req) stop("unexpected HTTP request"))
  expect_error(scan_file(f), class = "virustotal_validation_error")
})

test_that("invalid upload URLs fail before uploading any file", {
  f <- withr::local_tempfile()
  writeBin(as.raw(0), f)
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  f <- local_sized_file(33 * 1024^2)
  for (url in list(NULL, list(), c("a", "b"), "not a URL", "http://example.com/upload",
                   "https://user:pass@example.com/upload", "https://example.com/upload#fragment")) {
    calls <- 0L
    httr2::local_mocked_responses(function(req) {
      calls <<- calls + 1L
      body <- jsonlite::toJSON(list(data = url), auto_unbox = TRUE)
      httr2::response(200, body = charToRaw(body))
    })
    expect_error(scan_file(f), class = "virustotal_error")
    expect_equal(calls, 1L)
  }
})

test_that("large uploads send the multipart file over HTTPS exactly once", {
  app <- webfakes::new_app()
  app$use(webfakes::mw_multipart())
  app$get("/api/v3/files/upload_url", function(req, res) {
    url <- paste0("https://", req$get_header("Host"), "/upload")
    res$send_json(list(data = url), auto_unbox = TRUE)
  })
  app$post("/upload", function(req, res) {
    res$send_json(list(data = list(
      type = "analysis", id = "fixture-analysis", size = length(req$files$file$value),
      bytes = as.integer(head(req$files$file$value, 4))
    )), auto_unbox = TRUE)
  })
  server <- webfakes::new_app_process(app, port = "0s")
  withr::defer(server$stop())
  local_mocked_bindings(vt_base_url = server$url("/api/v3", https = TRUE))
  perform <- httr2::req_perform
  local_mocked_bindings(req_perform = function(req) {
    req <- httr2::req_options(
      req, cainfo = system.file("cert/localhost/ca.crt", package = "webfakes")
    )
    perform(req)
  })
  f <- withr::local_tempfile()
  bytes <- as.raw(c(0, 10, 127, 255))
  writeBin(bytes, f)
  f <- local_sized_file(33 * 1024^2)
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  reset_rate_limit()
  withr::defer(reset_rate_limit())
  result <- scan_file(f)
  expect_equal(result$data$id, "fixture-analysis")
  expect_equal(unlist(result$data$bytes), as.integer(bytes))
  expect_equal(result$data$size, 33 * 1024^2)
  expect_equal(get_rate_limit_status()$requests_used, 2)
})

test_that("a failed single-use upload is not automatically replayed", {
  app <- webfakes::new_app()
  app$get("/api/v3/files/upload_url", function(req, res) {
    url <- paste0("https://", req$get_header("Host"), "/upload")
    res$send_json(list(data = url), auto_unbox = TRUE)
  })
  app$post("/upload", function(req, res) {
    res$set_status(503L)$set_header("Retry-After", "0")$send_json(list(error = "retry"))
  })
  server <- webfakes::new_app_process(app, port = "0s")
  withr::defer(server$stop())
  local_mocked_bindings(vt_base_url = server$url("/api/v3", https = TRUE))
  perform <- httr2::req_perform
  local_mocked_bindings(req_perform = function(req) {
    req <- httr2::req_options(
      req, cainfo = system.file("cert/localhost/ca.crt", package = "webfakes")
    )
    perform(req)
  })
  f <- local_sized_file(33 * 1024^2)
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  withr::local_options(virustotal.max_tries = 3)
  reset_rate_limit()
  withr::defer(reset_rate_limit())
  error <- tryCatch(scan_file(f), virustotal_error = identity)
  expect_s3_class(error, "virustotal_error")
  expect_equal(error$status_code, 503)
  expect_equal(get_rate_limit_status()$requests_used, 2)
})

test_that("legacy VirusTotal upload URLs are upgraded without altering their token", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  f <- local_sized_file(33 * 1024^2)
  urls <- character()
  httr2::local_mocked_responses(function(req) {
    urls <<- c(urls, req$url)
    body <- if (length(urls) == 1) {
      '{"data":"http://www.virustotal.com/_ah/upload/token?signature=a%2Fb"}'
    } else {
      '{"data":{"id":"fixture-analysis"}}'
    }
    httr2::response(200, body = charToRaw(body))
  })
  expect_equal(scan_file(f)$data$id, "fixture-analysis")
  expect_equal(urls[2], "https://www.virustotal.com/_ah/upload/token?signature=a%2Fb")
})

test_that("a single-use upload redirect is an error instead of an apparent success", {
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  f <- local_sized_file(33 * 1024^2)
  calls <- 0L
  httr2::local_mocked_responses(function(req) {
    calls <<- calls + 1L
    if (calls == 1L) {
      httr2::response(200, body = charToRaw('{"data":"https://www.virustotal.com/upload"}'))
    } else {
      expect_identical(req$options$followlocation, FALSE)
      httr2::response(307, headers = list(location = "https://example.com/upload"),
                      body = charToRaw('{"data":{"id":"not-an-analysis"}}'))
    }
  })
  error <- tryCatch(scan_file(f), virustotal_error = identity)
  expect_s3_class(error, "virustotal_error")
  expect_equal(error$status_code, 307)
  expect_equal(calls, 2L)
})
