#' Get URL Report
#'
#' Retrieve a scan report on a given URL
#' 
#' @param url url; string; required
#' @param scan numeric; optional; when set to 1, submits url for scan if no existing reports are found
#' 
#' @return data frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' url_report(url="http://www.google.com")
#' }

url_report <- function(url = NULL, scan=1) {

	key <- Sys.getenv("VirustotalToken")
    
    if (identical(key, "")) stop("Set API Key using set_key()")

    params <- list(resource = url, scan = scan, apikey=key)
    res    <- POST("https://www.virustotal.com/vtapi/v2/url/report", body = params)
    
    virustotal_check(res)

    if (identical(content(res), NULL)) return(NULL)

    as.data.frame(do.call(cbind,content(res)))
}

