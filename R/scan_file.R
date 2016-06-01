#' Submit file for scanning
#'
#' @param file_path Required; Path to the document
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return data.frame with the following columns: scan_id, sha1, resource, response_code, sha256, permalink, md5, verbose_msg
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' scan_file(file_path='path_to_suspicious_file')
#' }

scan_file <- function(file_path = NULL, ...) {

	if (!file.exists(file_path)) stop("File Doesn't Exist. Please check the path.")

    res   <- virustotal_POST(path="file/scan", body=list(file=upload_file(file_path)))

    as.data.frame(do.call(cbind, res))
}

