#' Set VirusTotal API Key
#'
#' Stores your VirusTotal API key in an environment variable for use by other
#' package functions. Get your API key from \url{https://www.virustotal.com/}.
#'  
#' @param api_key VirusTotal API key (character string). Required.
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
#' Sys.getenv("VirustotalToken")
#' }

set_key <- function(api_key) {
  # Handle missing argument
  if (missing(api_key)) {
    stop(virustotal_validation_error(
      message = "API key must be provided",
      parameter = "api_key",
      value = "missing"
    ))
  }
  
  # Input validation with proper error handling
  tryCatch({
    checkmate::assert_character(api_key, len = 1, any.missing = FALSE, min.chars = 1)
  }, error = function(e) {
    stop(virustotal_validation_error(
      message = "API key must be a non-empty character string",
      parameter = "api_key",
      value = if (is.null(api_key)) "NULL" else class(api_key)[1]
    ))
  })
  
  # Validate API key format (VirusTotal keys are typically 64 characters)
  if (nchar(api_key) < 32) {
    stop(virustotal_validation_error(
      message = "API key appears to be too short. VirusTotal keys are typically 64 characters.",
      parameter = "api_key",
      value = paste("Length:", nchar(api_key))
    ))
  }
  
  # Check for common mistakes
  if (grepl("^[[:space:]]+|[[:space:]]+$", api_key)) {
    api_key <- trimws(api_key)
    warning("Removed leading/trailing whitespace from API key.")
  }
  
  if (api_key == "your_api_key_here" || api_key == "api_key_here") {
    stop(virustotal_validation_error(
      message = "Please replace placeholder with your actual API key",
      parameter = "api_key",
      value = api_key
    ))
  }
  
  # Set the environment variable
  Sys.setenv(VirustotalToken = api_key)
  
  message("VirusTotal API key successfully set.")
  invisible(TRUE)
}
