#' Retrieve comments for a file
#'
#' @param hash File hash (MD5, SHA1, or SHA256)
#' @param limit Number of comments to retrieve. Integer. Optional. Default is 10.
#' @param cursor String for pagination. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return list containing file comments
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
#' get_file_comments(hash='99017f6eebbac24f351415dd410d522d')
#' }

get_file_comments <- function(hash = NULL, limit = NULL, cursor = NULL, ...) {

  if (is.null(hash) || !is.character(hash) || nchar(hash) == 0) {
    stop("Must specify a valid file hash (MD5, SHA1, or SHA256).\n")
  }

  res <- virustotal_GET(path = paste0("files/", hash, "/comments"),
                       query = list(limit = limit, cursor = cursor), ...)

  res
}
