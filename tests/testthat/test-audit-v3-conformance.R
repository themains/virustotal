# Offline tests for defects found by auditing the package against the
# VirusTotal API v3 reference. Nothing here touches the network.

# Replace both HTTP choke points and record what each function asked for.
new_capture <- function(response = list(data = list(id = "x", type = "file"))) {
  cap <- new.env(parent = emptyenv())
  cap$calls <- list()
  cap$get <- function(path, query = list(), key = "fake", ...) {
    cap$calls[[length(cap$calls) + 1L]] <- list(verb = "GET", path = path,
                                                query = query, dots = list(...))
    response
  }
  cap$post <- function(path, body = NULL, query = list(), key = "fake", ...) {
    cap$calls[[length(cap$calls) + 1L]] <- list(verb = "POST", path = path,
                                                query = query, body = body,
                                                dots = list(...))
    response
  }
  cap$last <- function() cap$calls[[length(cap$calls)]]
  cap
}

use_capture <- function(cap, env = parent.frame()) {
  testthat::local_mocked_bindings(virustotal_GET = cap$get,
                                  virustotal_POST = cap$post,
                                  .package = "virustotal", .env = env)
}

# The reference implementation of a v3 URL identifier:
#   base64.urlsafe_b64encode(url.encode()).decode().strip("=")
# Base64 is computed here in plain R, sharing no code with the package's
# openssl-based implementation, so agreement between the two is evidence.
urlsafe_id <- function(u) {
  alphabet <- c(LETTERS, letters, as.character(0:9), "-", "_")
  bytes <- as.integer(charToRaw(u))
  bits <- as.vector(vapply(
    bytes, function(b) as.integer(intToBits(b))[8:1], integer(8)
  ))
  pad <- (6 - length(bits) %% 6) %% 6
  bits <- c(bits, rep(0L, pad))
  idx <- vapply(
    seq(1, length(bits), by = 6),
    function(i) sum(bits[i:(i + 5)] * 2^(5:0)),
    numeric(1)
  )
  paste(alphabet[idx + 1], collapse = "")
}

test_that("URL identifiers use the URL-safe base64 alphabet", {
  # A standard-alphabet '/' inside the identifier becomes a path separator and
  # the request addresses an endpoint that does not exist.
  cap <- new_capture(); use_capture(cap)
  urls <- c("http://www.google.com",
            "https://shop.example.org/cart?sku=99&ref=abc",
            "https://en.wikipedia.org/wiki/Malware",
            "https://stackoverflow.com/questions/1732348/regex-match-open-tags")
  for (u in urls) {
    url_report(u)
    expect_equal(sub("^urls/", "", cap$last()$path), urlsafe_id(u), info = u)
  }
  for (fn in c("get_url_comments", "get_url_votes")) {
    do.call(fn, list("https://shop.example.org/cart?sku=99&ref=abc"))
    expect_equal(sub("^urls/([^/]+)/.*$", "\\1", cap$last()$path),
                 urlsafe_id("https://shop.example.org/cart?sku=99&ref=abc"),
                 info = fn)
  }
})

test_that("no assembled path contains a stray slash in its identifier", {
  cap <- new_capture(); use_capture(cap)
  url_report("https://shop.example.org/cart?sku=99&ref=abc")
  expect_equal(length(strsplit(cap$last()$path, "/", fixed = TRUE)[[1]]), 2)
})

test_that("rescan endpoints use the v3 /analyse verb", {
  # /rescan is the v2 path. rescan_file() already used /analyse.
  cap <- new_capture(); use_capture(cap)
  rescan_domain("google.com")
  expect_equal(cap$last()$path, "domains/google.com/analyse")
  rescan_ip("8.8.8.8")
  expect_equal(cap$last()$path, "ip_addresses/8.8.8.8/analyse")
  rescan_file("99017f6eebbac24f351415dd410d522d")
  expect_equal(cap$last()$path, "files/99017f6eebbac24f351415dd410d522d/analyse")
})

test_that("rescan_url base64-encodes the identifier like its siblings", {
  cap <- new_capture(); use_capture(cap)
  u <- "http://www.google.com"
  rescan_url(u)
  expect_equal(cap$last()$path, paste0("urls/", urlsafe_id(u), "/analyse"))
})

test_that("get_domain_votes strips an https:// scheme like its siblings", {
  cap <- new_capture(); use_capture(cap)
  for (fn in c("get_domain_info", "get_domain_comments", "get_domain_votes")) {
    do.call(fn, list("https://www.google.com"))
    expect_false(grepl("//", sub("^[^/]*/", "", cap$last()$path)), info = fn)
    expect_true(startsWith(cap$last()$path, "domains/www.google.com"), info = fn)
  }
})

test_that("scan_file uploads as multipart/form-data", {
  # POST /files requires multipart with a binary part named 'file'. A JSON
  # encoder has no method for an httr form_file, so this failed before any I/O.
  cap <- new_capture(); use_capture(cap)
  f <- tempfile()
  on.exit(unlink(f), add = TRUE)
  writeBin(as.raw(c(0x4d, 0x5a, 0x90, 0x00)), f)
  expect_no_error(scan_file(f))
  expect_equal(cap$last()$path, "files")
  expect_equal(cap$last()$dots$encode, "multipart")
})

test_that("scan_url posts a form-encoded url field", {
  # POST /urls declares only application/x-www-form-urlencoded.
  cap <- new_capture(); use_capture(cap)
  scan_url("http://www.google.com")
  expect_equal(cap$last()$path, "urls")
  expect_equal(cap$last()$body$url, "http://www.google.com")
  expect_equal(cap$last()$dots$encode, "form")
})

test_that("comment and vote bodies are still JSON-encoded", {
  # Only the two scan endpoints change encoding; the rest stay JSON.
  cap <- new_capture(); use_capture(cap)
  post_url_comments("http://www.google.com", "nice")
  expect_true(is.null(cap$last()$dots$encode) ||
                identical(cap$last()$dots$encode, "json"))
  expect_equal(cap$last()$body$data$type, "comment")
})

test_that("print and summary methods are registered for dispatch", {
  # Without S3method() entries in NAMESPACE these never run for a user, even
  # though the man pages document them.
  for (m in c("print.virustotal_response", "print.virustotal_file_report",
              "print.virustotal_domain_report", "print.virustotal_error",
              "summary.virustotal_response")) {
    parts <- strsplit(m, ".", fixed = TRUE)[[1]]
    expect_true(
      !is.null(utils::getS3method(parts[1], paste(parts[-1], collapse = "."),
                                  optional = TRUE)),
      info = m)
  }
})

test_that("print dispatches for a caller outside the package namespace", {
  # The existing suite passes because test code is evaluated in an environment
  # whose parent is the namespace, where dispatch finds the function anyway.
  # A real user's environment does not have that parent.
  user_env <- new.env(parent = globalenv())
  user_env$e <- virustotal_error("Test error", status_code = 404)
  out <- evalq(capture.output(print(e)), user_env)
  expect_true(any(grepl("VirusTotal API Error: Test error", out, fixed = TRUE)))
})

test_that("retry_after falls back to 60 when the header is absent", {
  # as.numeric(NULL) is numeric(0), not NULL, so a %||% fallback never fired
  # and a zero-length value propagated into the condition object.
  check <- get("virustotal_check", envir = asNamespace("virustotal"))
  e <- tryCatch(check(httr2::response(429)), error = function(e) e)
  expect_equal(e$retry_after, 60)
  e <- tryCatch(
    check(httr2::response(429, headers = list("retry-after" = "37"))),
    error = function(e) e
  )
  expect_equal(e$retry_after, 37)
})
