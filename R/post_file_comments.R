#' Add a comment to a file
#'
#' @param hash File hash (MD5, SHA1, or SHA256)
#' @param comment Comment text to add
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return list containing response data
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
#' post_file_comments(hash='99017f6eebbac24f351415dd410d522d', 
#'                    comment='This file appears to be suspicious')
#' }

post_file_comments <- function(hash = NULL, comment = NULL, ...) {

  # Validate inputs using checkmate
  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)
  assert_character(comment, len = 1, any.missing = FALSE, min.chars = 1)

  res <- virustotal_POST(path = paste0("files/", hash, "/comments"),
                        body = list(data = list(type = "comment", 
                                               attributes = list(text = comment))), ...)

  res
}
