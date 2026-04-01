#' Get File Behaviours
#'
#' Retrieves all behaviour reports for a file from various sandboxes.
#'
#' @param hash File hash (MD5, SHA1, or SHA256). Required.
#' @param limit Number of reports to retrieve. Integer. Optional.
#' @param cursor String for pagination. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return list containing behaviour reports from various sandboxes
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{get_file_behaviour_summary}} for summary,
#'   \code{\link{get_behaviour_report}} for individual sandbox reports
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' get_file_behaviours(hash='99017f6eebbac24f351415dd410d522d')
#' get_file_behaviours(hash='99017f6eebbac24f351415dd410d522d', limit=5)
#' }

get_file_behaviours <- function(hash = NULL, limit = NULL, cursor = NULL, ...) {

  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)

  res <- virustotal_GET(
    path = paste0("files/", hash, "/behaviours"),
    query = list(limit = limit, cursor = cursor),
    ...
  )

  res
}
