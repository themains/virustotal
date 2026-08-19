#' Package startup and cleanup functions
#'
#' @name virustotal-package
#' @keywords internal
NULL

#' @importFrom utils packageDescription
.onLoad <- function(libname, pkgname) {
  # The key is resolved lazily by vt_key() at call time, so loading the
  # package no longer mutates the environment.
  init_rate_limit()
}

.onUnload <- function(libpath) {
  if (exists(".virustotal_state", envir = asNamespace("virustotal"))) {
    rm(list = ls(.virustotal_state), envir = .virustotal_state)
  }
}
