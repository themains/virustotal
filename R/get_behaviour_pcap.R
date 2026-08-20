#' Get Behaviour PCAP File
#'
#' Retrieves the PCAP (network capture) file from a sandbox analysis.
#'
#' @param sandbox_id Sandbox report ID (character string). Required.
#' @param output_path Local path to save the PCAP file. Optional.
#' @param \dots Ignored. Configure requests with the package options
#'   instead (see \code{\link{virustotal}}).
#'
#' @return Raw PCAP content or saves to file if output_path specified
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
#' pcap <- get_behaviour_pcap(sandbox_id = 'hash_sandboxname')
#' get_behaviour_pcap(
#'   sandbox_id = 'hash_sandboxname',
#'   output_path = '/tmp/capture.pcap'
#' )
#' }
get_behaviour_pcap <- function(sandbox_id = NULL, output_path = NULL, ...) {
  assert_character(sandbox_id, len = 1, any.missing = FALSE, min.chars = 1)

  if (!is.null(output_path)) {
    assert_character(output_path, len = 1, any.missing = FALSE, min.chars = 1)
  }

  raw_body <- virustotal_GET_raw(paste0("file_behaviours/", sandbox_id, "/pcap"), ...)

  if (!is.null(output_path)) {
    writeBin(raw_body, output_path)
    paste("PCAP file saved to:", output_path)
  } else {
    raw_body
  }
}
