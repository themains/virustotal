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
	file_name <- basename(file_path)
	file <- paste("file", file_name, body)

    res   <- virustotal_POST(path="file/scan", query=list(file=file_name), body= upload_file(file_path), encode="multipart", ...)

    as.data.frame(do.call(cbind, res))
}

