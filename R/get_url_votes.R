#' Retrieve votes for a URL
#'
#' @param url_id URL or URL ID from VirusTotal
#' @param limit Number of votes to retrieve. Integer. Optional. Default is 10.
#' @param cursor String for pagination. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return list containing URL votes
#'  
#' @export
#' 
#' @references \url{https://docs.virustotal.com/reference}
#' 
#' @seealso \code{\link{set_key}} for setting the API key
#'
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' get_url_votes(url_id='http://www.google.com')
#' }

get_url_votes <- function(url_id = NULL, limit = NULL, cursor = NULL, ...) {

  if (is.null(url_id) || !is.character(url_id) || nchar(url_id) == 0) {
    stop("Must specify a valid URL or URL ID.\n")
  }

  # If it looks like a URL, encode it to base64 (VirusTotal v3 requirement)
  if (grepl("^https?://", url_id)) {
    url_id <- base64enc::base64encode(charToRaw(url_id))
    url_id <- gsub("=+$", "", url_id)  # Remove padding
  }

  res <- virustotal_GET(path = paste0("urls/", url_id, "/votes"),
                       query = list(limit = limit, cursor = cursor), ...)

  res
}
