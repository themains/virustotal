#' Download a file from VirusTotal
#'
#' @param hash File hash (MD5, SHA1, or SHA256)
#' @param output_path Local path to save the downloaded file. Optional.
#' @param \dots Ignored. Configure requests with the package options
#'   instead (see \code{\link{virustotal}}).
#'
#' @return Raw file content or saves file to specified path
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
#' download_file(hash='99017f6eebbac24f351415dd410d522d',
#'               output_path='/tmp/downloaded_file')
#' }

download_file <- function(hash = NULL, output_path = NULL, ...) {

  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)

  if (!is.null(output_path)) {
    assert_character(output_path, len = 1, any.missing = FALSE, min.chars = 1)
  }

  raw_body <- virustotal_GET_raw(paste0("files/", hash, "/download"))

  if (!is.null(output_path)) {
    writeBin(raw_body, output_path)
    return(paste("File downloaded to:", output_path))
  } else {
    return(raw_body)
  }
}
