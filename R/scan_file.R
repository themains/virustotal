#' Submit file for scanning
#'
#' @param file_path Required; Path to the document
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return data.frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' scan_file(file_path='path_to_suspicious_file')
#' }

scan_file <- function(file_path = NULL, ...) {

	if (!file.exists(file_path)) stop("File Doesn't Exist. Please check the path.")

	body  <- upload_file(file_path)

    res   <- virustotal_POST(path="file/scan", query = list(), body=body, ...)

    as.data.frame(do.call(cbind, content(res)))
}

