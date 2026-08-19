#' Get File Behaviour Summary
#'
#' Retrieves a summary of all behaviour reports for a file.
#'
#' @param hash File hash (MD5, SHA1, or SHA256). Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return list containing behaviour summary from all sandboxes
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference/file-all-behaviours-summary}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{get_file_behaviours}} for full behaviour reports
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' get_file_behaviour_summary(hash = '99017f6eebbac24f351415dd410d522d')
#' }
get_file_behaviour_summary <- function(hash = NULL, ...) {
  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)

  res <- virustotal_GET(path = paste0("files/", hash, "/behaviour_summary"), ...)

  res
}
