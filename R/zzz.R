#' Package startup and cleanup functions
#'
#' @name virustotal-package
#' @keywords internal
NULL

#' @importFrom utils packageDescription
.onLoad <- function(libname, pkgname) {
  # Initialize rate limiting state when package loads
  init_rate_limit()
  
  # Optionally set a default API key if environment variable exists
  # (but don't override if already set)
  if (Sys.getenv("VirustotalToken") == "" && Sys.getenv("VIRUSTOTAL_API_KEY") != "") {
    Sys.setenv(VirustotalToken = Sys.getenv("VIRUSTOTAL_API_KEY"))
  }
}

.onUnload <- function(libpath) {
  # Clean up rate limiting state
  if (exists(".virustotal_state", envir = asNamespace("virustotal"))) {
    rm(list = ls(.virustotal_state), envir = .virustotal_state)
  }
}