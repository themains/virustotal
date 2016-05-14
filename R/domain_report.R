#' Get Domain Report
#'
#' @param domain domain name (string)
#' 
#' @return data frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' domain_report(domain="http://www.google.com")
#' }

domain_report <- function(domain = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    if (identical(key, "")) stop("Set API Key using set_key()")

    params <- list(domain = domain, apikey=key)
    
    res <- GET("http://www.virustotal.com/vtapi/v2/domain/report", body = params)

    virustotal_check(res)

    as.data.frame(do.call(cbind, content(res)))
}

