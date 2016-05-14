#' Submit file for scanning
#'
#' @param file_path Required; Path to the document
#' 
#' @return data.frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' scan_file(file_path='path_to_suspicious_file')
#' }

scan_file <- function(file_path = NULL) {

	key <- Sys.getenv("VirustotalToken")
    
    if (identical(key, "")) stop("Set API Key using set_key()")

	if (!file.exists(file_path)) stop("File Doesn't Exist. Please check the path.")

    params <- list(apikey=key)
	body   <- upload_file(file_path)

    res    <- POST("http://www.virustotal.com/vtapi/v2/file/scan", query=params, body=body)

    virustotal_check(res)

    as.data.frame(do.call(cbind, content(res)))
}

