#' Get URL Report
#'
#' Retrieve a scan report for a given URL or URL ID from VirusTotal.
#' 
#' @param url_id URL or URL ID from VirusTotal. String. Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'  
#' @return list containing URL analysis results including scan details,
#' detection information, and metadata
#'  
#' @export
#' 
#' @references \url{https://docs.virustotal.com/reference}
#' 
#' @seealso \code{\link{set_key}} for setting the API key, \code{\link{scan_url}} for submitting URLs
#'
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' # Get report using URL
#' url_report("http://www.google.com")
#' 
#' # Get report using URL ID (base64 encoded URL without padding)
#' url_report("687474703a2f2f7777772e676f6f676c652e636f6d2f")
#' }

url_report <- function(url_id = NULL, ...) {

  # Validate URL ID using checkmate
  assert_character(url_id, len = 1, any.missing = FALSE, min.chars = 1)

  # If it looks like a URL, encode it to base64 (VirusTotal v3 requirement)
  if (grepl("^https?://", url_id)) {
    url_id <- base64enc::base64encode(charToRaw(url_id))
    url_id <- gsub("=+$", "", url_id)  # Remove padding
  }

  res <- virustotal_GET(path = paste0("urls/", url_id), ...)

  res
}
