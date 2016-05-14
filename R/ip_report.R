#' Get URL Report
#'
#' @param ip IP Address (String)
#' 
#' @return list
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' ip_report(ip="8.8.8.8")
#' }

ip_report <- function(ip = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    params <- list(ip = ip, apikey=key)
    res    <- GET("http://www.virustotal.com/vtapi/v2/ip-address/report", query = params)

    virustotal_check(res)

    content(res)
}

