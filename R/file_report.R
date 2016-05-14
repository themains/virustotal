#' Get File Scan Report
#'
#' @param hash Hash for the scan
#' 
#' @return data.frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' file_report(hash='99017f6eebbac24f351415dd410d522d')
#' }

file_report <- function(hash = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    if (identical(key, "")) stop("Set API Key using set_key()")

    params <- list(resource = hash, apikey=key)
    res    <- GET("https://www.virustotal.com/vtapi/v2/file/report", query = params)

    virustotal_check(res)

    content(res)
}

