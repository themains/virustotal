#' Set VirusTotal API Key
#'
#' Stores your VirusTotal API key in an environment variable for use by other
#' package functions. Get your API key from \url{https://www.virustotal.com/}.
#'
#' The canonical environment variable is \code{VIRUSTOTAL_API_KEY}; the
#' historical \code{VirustotalToken} is also set for compatibility with code
#' that reads it directly. Setting either variable before loading the package
#' works without calling this function at all.
#'
#' @param api_key VirusTotal API key. After trimming surrounding whitespace, the
#'   key must contain at least 32 ASCII letters or digits.
#'
#' @return Invisibly returns TRUE on success
#' @export
#' @family authentication
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @examples \dontrun{
#' # Set your API key
#' set_key('your_64_character_api_key_here')
#'
#' # Verify it's set
#' is_api_key_configured()
#' }
set_key <- function(api_key = NULL) {
  if (is.null(api_key)) {
    stop(virustotal_validation_error(
      message = "API key must be provided",
      parameter = "api_key",
      value = "NULL"
    ))
  }

  tryCatch(
    {
      assert_character(api_key, len = 1, any.missing = FALSE, min.chars = 1)
    },
    error = function(e) {
      stop(virustotal_validation_error(
        message = "API key must be a non-empty character string",
        parameter = "api_key",
        value = if (is.null(api_key)) "NULL" else class(api_key)[1]
      ))
    }
  )

  key <- trimws(api_key)
  if (!valid_vt_key(key)) {
    stop(virustotal_validation_error(
      message = "API key must contain at least 32 letters or digits.",
      parameter = "api_key",
      value = paste("Length:", nchar(key))
    ))
  }
  if (!identical(key, api_key)) warning("Removed leading/trailing whitespace from API key.")

  Sys.setenv(VIRUSTOTAL_API_KEY = key, VirustotalToken = key)

  message("VirusTotal API key successfully set.")
  invisible(TRUE)
}
