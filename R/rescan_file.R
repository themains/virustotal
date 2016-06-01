#' Rescan already submitted files
#'
#' @param hash Hash for the scan
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return data.frame with 12 columns: scans, scan_id, sha1, resource, response_code, scan_date
#' permalink, verbose_msg, total, positives, sha256, md5   
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' rescan_file(hash='99017f6eebbac24f351415dd410d522d')
#' }

rescan_file <- function(hash = NULL, ...) {

	if (!is.character(hash)) {
        stop("Must specify the hash.")
    }

    params <- list(resource = hash)

    res   <- virustotal_POST(path="file/rescan", query = params, ...)

    as.data.frame(do.call(cbind, content(res)))
}

