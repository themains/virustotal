#' Get file upload URL for large files
#'
#' Get a special URL for uploading files larger than 32MB to VirusTotal for analysis.
#' 
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return list containing upload URL and other metadata
#'  
#' @export
#' 
#' @references \url{https://docs.virustotal.com/reference}
#' 
#' @seealso \code{\link{set_key}} for setting the API key, \code{\link{scan_file}} for regular file uploads
#'
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' get_file_upload_url()
#' }

get_file_upload_url <- function(...) {

  res <- virustotal_GET(path = "files/upload_url", ...)

  res
}
