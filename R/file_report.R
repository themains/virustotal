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

file_report <- function(hash = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    params <- list(resource = hash, apikey=key)
    res    <- GET("https://www.virustotal.com/vtapi/v2/file/report", query = params)

    if (identical(content(res), NULL)) return(NULL)

    as.data.frame(do.call(cbind,content(res)))
}

