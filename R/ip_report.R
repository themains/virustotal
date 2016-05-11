#' Get URL Report
#'
#' @param ip IP Address (String)
#' 
#' @return data frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' ip_report(ip="8.8.8.8")
#' }

ip_report <- function(ip = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    params <- list(ip = ip, apikey=key)
    res    <- GET("https://www.virustotal.com/vtapi/v2/ip/report", query = params)
    as.data.frame(do.call(cbind,content(res)))
}

