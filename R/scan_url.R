#' Submit URL for scanning
#' 
#' Submit a URL for analysis. Returns analysis details including an ID that can be used to 
#' retrieve the report using \code{\link{url_report}}
#' 
#' @param url URL to scan; string; required
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return list containing analysis details and ID
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
#' scan_url("http://www.google.com")
#' }

scan_url <- function(url = NULL, ...) {

  # Validate URL using checkmate
  assert_character(url, len = 1, any.missing = FALSE, min.chars = 1)

  res <- virustotal_POST(path = "urls", 
                        body = list(url = url), ...)

  res
}
