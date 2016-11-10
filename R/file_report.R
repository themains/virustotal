#' Get File Scan Report
#'
#' @param hash Hash for the scan
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return data.frame with 12 columns: 
#' \code{scans, scan_id, sha1, resource, response_code, scan_date, permalink, verbose_msg, total, positives, sha256, md5}   
#'  
#' @export
#' 
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' 
#' @seealso \code{\link{set_key}} for setting the API key
#' 
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' file_report(hash='99017f6eebbac24f351415dd410d522d')
#' }

file_report <- function(hash = NULL, ...) {

    if (!is.character(hash)) {
        stop("Must specify hash")
    }

    params <- list(resource = hash)
    res    <- virustotal_GET(path="file/report", query = params, ...)

    as.data.frame(do.call(cbind, res))
}

