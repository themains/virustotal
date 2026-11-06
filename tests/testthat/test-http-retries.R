test_that("real HTTP retries recover and count every response", {
  app <- webfakes::new_app()
  app$get("/api/v3/domains/:mode", local({
    counts <- list()
    function(req, res) {
      mode <- req$params$mode
      n <- counts[[mode]]
      if (is.null(n)) n <- 0L
      counts[[mode]] <<- n + 1L
      if (n == 0L) {
        if (mode == "date") {
          res$set_header("Date", "Thu, 05 Nov 2026 12:00:00 GMT")
          res$set_header("Retry-After", "Thu, 05 Nov 2026 12:00:01 GMT")
        }
        res$set_status(if (mode == "date") 429L else 503L)$send_json(list(error = "retry"))
      } else {
        res$send_json(list(data = list(id = mode, attempts = n + 1L)), auto_unbox = TRUE)
      }
    }
  }))
  server <- webfakes::new_app_process(app)
  withr::defer(server$stop())
  local_mocked_bindings(vt_base_url = server$url("/api/v3"))
  withr::local_options(virustotal.max_tries = 2, virustotal.max_retry_wait = 0)
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  withr::defer(reset_rate_limit())
  for (mode in c("missing", "date")) {
    reset_rate_limit()
    result <- get_domain_info(mode)
    expect_equal(result$data$attempts, 2)
    expect_equal(get_rate_limit_status()$requests_used, 2)
  }
})

test_that("exhausted retries and single attempts are counted without duplication", {
  app <- webfakes::new_app()
  app$get("/api/v3/domains/example.com", function(req, res) {
    res$set_status(429L)$set_header("Retry-After", "0")$send_json(list(error = "quota"))
  })
  server <- webfakes::new_app_process(app)
  withr::defer(server$stop())
  local_mocked_bindings(vt_base_url = server$url("/api/v3"))
  withr::local_envvar(c(VIRUSTOTAL_API_KEY = strrep("a", 64)))
  withr::defer(reset_rate_limit())
  for (attempts in c(1, 3)) {
    withr::local_options(virustotal.max_tries = attempts)
    reset_rate_limit()
    expect_error(get_domain_info("example.com"), class = "virustotal_rate_limit_error")
    expect_equal(get_rate_limit_status()$requests_used, attempts)
  }
})
