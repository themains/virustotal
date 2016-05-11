#' Get File Scan Report
#'
#' @param hash Hash for the scan
#' 
#' @return data frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' file_report(hash='hash')
#' }

ip_report <- function(hash = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    params <- list(ip = ip, apikey=key)
    res    <- GET("https://www.virustotal.com/vtapi/v2/ip/report", query = params)
    as.data.frame(do.call(cbind,content(res)))
}

