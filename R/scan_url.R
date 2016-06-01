#' Submit URL for scanning
#' 
#' @param url url; string; required
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return data.frame with 7 columns: permalink, resource, url, response_code, scan_date, scan_id, verbose_msg
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' scan_url("http://www.google.com")
#' }

scan_url <- function(url = NULL, ...) {

    if (!is.character(url)) {
        stop("Must specify url")
    }

    res    <- virustotal_POST(path="url/scan", query = list(url = url), ...)
    
    as.data.frame(do.call(cbind, res))
}

