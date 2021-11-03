#' Submit URL for scanning
#' 
#' Submit a URL for scanning. Returns a data.frame with \code{scan_id} which can be used to 
#' fetch the report using \code{\link{url_report}}
#' 
#' @param url url; string; required
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return data.frame with 7 columns: 
#' \code{permalink, resource, url, response_code, scan_date, scan_id, verbose_msg}
#'  
#' @export
#' 
#' @references \url{https://developers.virustotal.com/v2.0/reference}
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

  if (!is.character(url)) {
    stop("Must specify a valid url.\n")
  }

  res    <- virustotal_POST(path = "url/scan", query = list(url = url), ...)

  as.data.frame(res)
}
