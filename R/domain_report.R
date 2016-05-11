#' Get Domain Report
#'
#' @param domain
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
    
    params <- list(domain = domain, apikey=key)
    
    res <- GET("http://www.virustotal.com/vtapi/v2/domain/report", body = params)

    if (identical(content(res), NULL)) return(NULL)

    as.data.frame(do.call(cbind, content(res)))
}

