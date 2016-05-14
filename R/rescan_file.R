#' Rescan already submitted files
#'
#' @param hash Hash for the scan
#' 
#' @return data.frame with 12 columns: scans, scan_id, sha1, resource, response_code, scan_date
#' permalink, verbose_msg, total, positives, sha256, md5   
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' rescan_file(hash='99017f6eebbac24f351415dd410d522d')
#' }

rescan_file <- function(hash = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    if (identical(key, "")) stop("Set API Key using set_key()")

    params <- list(resource = hash, apikey=key)
    res    <- POST("https://www.virustotal.com/vtapi/v2/file/rescan", query = params)

    virustotal_check(res)

    as.data.frame(do.call(cbind, content(res)))
}

