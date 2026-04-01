#' Get Behaviour Report
#'
#' Retrieves a specific behaviour report from a sandbox analysis.
#'
#' @param sandbox_id Sandbox report ID (character string). Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return list containing detailed behaviour report from the sandbox
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{get_file_behaviours}} for listing all behaviour reports
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' get_behaviour_report(sandbox_id='hash_sandboxname')
#' }

get_behaviour_report <- function(sandbox_id = NULL, ...) {

  assert_character(sandbox_id, len = 1, any.missing = FALSE, min.chars = 1)

  res <- virustotal_GET(path = paste0("file_behaviours/", sandbox_id), ...)

  res
}
