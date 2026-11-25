#' Retrieve relationships for a file
#'
#' @param hash File hash (MD5, SHA1, or SHA256)
#' @param relationship A VirusTotal relationship name such as `graphs`.
#' @param limit Number of relationships to retrieve. Integer. Optional. Default is 10.
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
#' get_file_relationships(
#'   hash = '99017f6eebbac24f351415dd410d522d',
#'   relationship = 'contacted_domains'
#' )
#' }
get_file_relationships <- function(hash = NULL, relationship = NULL,
                                   limit = NULL, cursor = NULL, ...) {
  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)
  validate_relationship(relationship)

  res <- virustotal_GET(
    path = paste0("files/", hash, "/relationships/", relationship),
    query = list(limit = limit, cursor = cursor), ...
  )

  res
}
