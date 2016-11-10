#' Rescan already submitted files
#' 
#' The function returns a data.frame with a \code{scan_id} and \code{sha256}, \code{sha1}, \code{md5} hashes,
#' all of which can be used to retrieve the report using \code{\link{file_report}}
#' 
#' @param hash Hash for the scan. String. Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return data.frame with 12 columns: 
#' \code{scans, scan_id, sha1, resource, response_code, scan_date, permalink, verbose_msg, total, positives, sha256, md5}   
#' \code{response_code} is 0 if the file is not in the database (hash can't be found). 
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
#' rescan_file(hash='99017f6eebbac24f351415dd410d522d')
#' rescan_file(hash='99017f6ee51415dd410d522d') # incorrect hash
#' }

rescan_file <- function(hash = NULL, ...) {

	if (!is.character(hash)) {
        stop("Must specify the hash.")
    }

    params <- list(resource = hash)

    res   <- virustotal_POST(path="file/rescan", query = params, ...)

    if (res$response_code == 0 ){
    	res_df <- read.table(text = "", 
    					 col.names = c("scans", "scan_id", "sha1", "resource", "response_code", "scan_date", "permalink", "verbose_msg", "total", "positives", "sha256", "md5"))
    	res_df[1, match(names(res), names(res_df))] <- res
    	return(res_df)
    }
    

    as.data.frame(res)
}

