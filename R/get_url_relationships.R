#' Retrieve relationships for a URL
#'
#' @param url_id URL or URL ID from VirusTotal
#' @param relationship A VirusTotal relationship name such as `graphs`.
#' @param limit Number of relationships to retrieve. Optional.
#' @param cursor String for pagination. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return A list containing the IDs and types of the related objects.
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
#' get_url_relationships(
#'   url_id = 'http://www.google.com',
#'   relationship = 'communicating_files'
#' )
#' }
get_url_relationships <- function(url_id = NULL, relationship = NULL,
                                  limit = NULL, cursor = NULL, ...) {
  assert_character(url_id, len = 1, any.missing = FALSE, min.chars = 1)
  validate_relationship(relationship)

  url_id <- vt_url_id(url_id)

  path <- paste0("urls/", url_id, "/relationships/", relationship)
  res <- virustotal_GET(
    path = path,
    query = list(limit = limit, cursor = cursor), ...
  )

  res
}
