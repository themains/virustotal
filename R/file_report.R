#' Get File Scan Report
#'
#' @param hash File hash (MD5, SHA1, or SHA256) or file ID
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return list containing file analysis results including antivirus scans, 
#' file metadata, and threat detection information
#'  
#' @export
#' 
#' @references \url{https://docs.virustotal.com/reference}
#' 
#' @seealso \code{\link{set_key}} for setting the API key
#' 
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' file_report(hash='99017f6eebbac24f351415dd410d522d')
#' }

file_report <- function(hash = NULL, ...) {

    if (is.null(hash) || !is.character(hash) || nchar(hash) == 0) {
        stop("Must specify a valid file hash (MD5, SHA1, or SHA256).\n")
    }

    res <- virustotal_GET(path = paste0("files/", hash), ...)

    res
}
