#' Get download URL for a file
#'
#' @param hash File hash (MD5, SHA1, or SHA256)
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return list containing download URL and metadata
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
#' get_file_download_url(hash='99017f6eebbac24f351415dd410d522d')
#' }

get_file_download_url <- function(hash = NULL, ...) {

  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)

  res <- virustotal_GET(path = paste0("files/", hash, "/download_url"), ...)

  res
}
