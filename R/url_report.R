#' Get URL Report
#'
#' Retrieve a scan report on a given URL
#' 
#' @param url url; string; required
#' @param scan numeric; optional; when set to 1, submits url for scan if no existing reports are found
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'  
#' @return data frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' url_report(url="http://www.google.com")
#' }

url_report <- function(url = NULL, scan=1, ...) {

	if (!is.character(url)) {
        stop("Must specify url")
    }

    params <- list(resource = url, scan = scan)
    
    res   <- virustotal_POST(path="url/report", query = params, ...)
    
    if (identical(content(res), NULL)) return(NULL)

    as.data.frame(do.call(cbind,content(res)))
}

