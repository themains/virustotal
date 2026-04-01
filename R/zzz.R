#' Package startup and cleanup functions
#'
#' @name virustotal-package
#' @keywords internal
NULL

#' @importFrom utils packageDescription
.onLoad <- function(libname, pkgname) {
  init_rate_limit()

  vt_token <- Sys.getenv("VirustotalToken")
  vt_api_key <- Sys.getenv("VIRUSTOTAL_API_KEY")
  if (vt_token == "" && vt_api_key != "") {
    Sys.setenv(VirustotalToken = vt_api_key)
  }
}

.onUnload <- function(libpath) {
  if (exists(".virustotal_state", envir = asNamespace("virustotal"))) {
    rm(list = ls(.virustotal_state), envir = .virustotal_state)
  }
}
