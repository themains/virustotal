#' Get IP Report
#' 
#' Get passive DNS data and URLs detected by URL scanners 
#'
#' @param ip IP Address (String)
#' 
#' @return named list with the following items: undetected_referrer_samples, detected_downloaded_samples, detected_referrer_samples, undetected_downloaded_samples, detected_urls, undetected_downloaded_samples, 
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

    res_list <- content(res)

    # undetected_downloaded_samples <- as.data.frame(do.call(rbind, res_list$undetected_downloaded_samples))

    res_list 
}

