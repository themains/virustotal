#' Get Analysis Results
#'
#' Retrieves the results of a file or URL analysis by its analysis ID.
#'
#' @param id Analysis ID (character string). Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return list containing analysis results including status and detection stats
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference/analysis}
#'
#' @seealso \code{\link{set_key}} for setting the API key
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' get_analysis(id = 'NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTI4NTk')
#' }
get_analysis <- function(id = NULL, ...) {
  assert_character(id, len = 1, any.missing = FALSE, min.chars = 1)

  res <- virustotal_GET(path = paste0("analyses/", id), ...)

  res
}
