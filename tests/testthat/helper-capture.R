# Shared offline test machinery.
#
# new_capture()/use_capture() replace the two HTTP choke points at the
# binding level and record what each endpoint function asked for -- request
# shaping is tested with zero network. use_capture() also supplies a fake
# key so endpoints with a has_vt_key() guard run.

new_capture <- function(response = list(data = list(id = "x", type = "file"))) {
  cap <- new.env(parent = emptyenv())
  cap$calls <- list()
  cap$get <- function(path, query = list(), key = "fake", ...) {
    cap$calls[[length(cap$calls) + 1L]] <- list(
      verb = "GET", path = path,
      query = query, dots = list(...)
    )
    response
  }
  cap$post <- function(path, body = NULL, query = list(), key = "fake", ...) {
    cap$calls[[length(cap$calls) + 1L]] <- list(
      verb = "POST", path = path,
      query = query, body = body,
      dots = list(...)
    )
    response
  }
  cap$last <- function() cap$calls[[length(cap$calls)]]
  cap
}

use_capture <- function(cap, env = parent.frame()) {
  withr::local_envvar(
    c(VIRUSTOTAL_API_KEY = strrep("a", 64)),
    .local_envir = env
  )
  testthat::local_mocked_bindings(
    virustotal_GET = cap$get,
    virustotal_POST = cap$post,
    .package = "virustotal", .env = env
  )
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
