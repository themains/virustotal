#' Submit file for scanning
#'
#' @param file_path Required; Path to the document
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return data.frame with the following columns: 
#' \code{scan_id, sha1, resource, response_code, sha256, permalink, md5, verbose_msg}
#'  
#' @export
#' 
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' 
#' @seealso \code{\link{set_key}} for setting the API key
#'
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' scan_file(file_path='path_to_suspicious_file')
#' }

scan_file <- function(file_path = NULL, ...) {

	if (!file.exists(file_path)) stop("File Doesn't Exist. Please check the path.")

    res   <- virustotal_POST(path="file/scan", body=list(file=upload_file(file_path)))

    as.data.frame(do.call(cbind, res))
}

