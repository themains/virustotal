#' Resolve the VirusTotal API key
#'
#' The canonical environment variable is \code{VIRUSTOTAL_API_KEY};
#' \code{VirustotalToken} is the historical name and is still honored.
#' \code{set_key()} sets both.
#'
#' @return The API key. Throws a \code{virustotal_auth_error} if none is set.
#' @keywords internal
#' @family authentication
vt_key <- function() {
  key <- Sys.getenv("VIRUSTOTAL_API_KEY")
  if (!nzchar(key)) key <- Sys.getenv("VirustotalToken")
  if (!nzchar(key)) {
    stop(virustotal_auth_error(
      message = paste(
        "No API key set. Use set_key() or set the",
        "VIRUSTOTAL_API_KEY environment variable."
      )
    ))
  }
  key
}

#' Is an API key set in either environment variable?
#'
#' @return Logical.
#' @keywords internal
#' @family authentication
has_vt_key <- function() {
  nzchar(Sys.getenv("VIRUSTOTAL_API_KEY")) ||
    nzchar(Sys.getenv("VirustotalToken"))
}
