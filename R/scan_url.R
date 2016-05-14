#' Submit URL for Scanning
#' 
#' @param url url; string; required
#' 
#' @return data frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' scan_url(url="http://www.google.com")
#' }

scan_url <- function(url = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    if (identical(key, "")) stop("Set API Key using set_key()")

    params <- list(url = url, apikey=key)
    res    <- POST("https://www.virustotal.com/vtapi/v2/url/scan", query = params)
    
    virustotal_check(res)

    as.data.frame(do.call(cbind,content(res)))
}

