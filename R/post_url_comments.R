#' Add a comment to a URL
#'
#' @param url_id URL or URL ID from VirusTotal
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
#' post_url_comments(url_id='http://www.google.com',
#'                   comment='This URL appears suspicious')
#' }

post_url_comments <- function(url_id = NULL, comment = NULL, ...) {

  assert_character(url_id, len = 1, any.missing = FALSE, min.chars = 1)
  assert_character(comment, len = 1, any.missing = FALSE, min.chars = 1)

  # If it looks like a URL, encode it to base64 (VirusTotal v3 requirement)
  if (grepl("^https?://", url_id)) {
    url_id <- base64encode(charToRaw(url_id))
    url_id <- gsub("=+$", "", url_id)  # Remove padding
  }

  res <- virustotal_POST(path = paste0("urls/", url_id, "/comments"),
                        body = list(data = list(type = "comment",
                                               attributes = list(text = comment))), ...)

  res
}
