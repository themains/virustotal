#' Get Behaviour HTML Report
#'
#' Retrieves a detailed HTML report from a sandbox analysis.
#'
#' @param sandbox_id Sandbox report ID (character string). Required.
#' @param output_path Local path to save the HTML file. Optional.
#' @param \dots Ignored. Configure requests with the package options
#'   instead (see \code{\link{virustotal}}).
#'
#' @return Raw HTML content or saves to file if output_path specified
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{get_behaviour_report}} for JSON report
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' html <- get_behaviour_html(sandbox_id='hash_sandboxname')
#' get_behaviour_html(sandbox_id='hash_sandboxname',
#'                    output_path='/tmp/report.html')
#' }

get_behaviour_html <- function(sandbox_id = NULL, output_path = NULL, ...) {

  assert_character(sandbox_id, len = 1, any.missing = FALSE, min.chars = 1)

  if (!is.null(output_path)) {
    assert_character(output_path, len = 1, any.missing = FALSE, min.chars = 1)
  }

  raw_body <- virustotal_GET_raw(paste0("file_behaviours/", sandbox_id, "/html"))

  if (!is.null(output_path)) {
    writeBin(raw_body, output_path)
    return(paste("HTML report saved to:", output_path))
  } else {
    return(raw_body)
  }
}
