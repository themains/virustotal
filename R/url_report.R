#' Get URL Report
#'
#' Retrieve a scan report for a given URL
#' 
#' @param url url; string; required
#' @param scan numeric; optional; when set to 1, submits url for scan if no existing reports are found; default is 1.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'  
#' @return data.frame with 12 columns: scan_id, resource, url, response_code, scan_date, permalink, verbose_msg, positives, total, detected, result, detail
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' url_report("http://www.google.com")
#' }

url_report <- function(url = NULL, scan = 1, ...) {

	if (!is.character(url)) {
        stop("Must specify url")
    }

    params <- list(resource = url, scan = scan)
    
    res   <- virustotal_POST(path="url/report", query = params, ...)
    
    if (identical(res, NULL)) return(NULL)

    res_10 <- do.call(cbind, lapply(res[1:10], unlist))
    res_11 <- do.call(plyr::rbind.fill, lapply(res[[11]], as.data.frame))
    cbind(res_10, res_11)
}

