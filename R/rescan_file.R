#' Request rescan of a file
#' 
#' Request a new analysis of a file already present in VirusTotal's database.
#' Returns an analysis ID that can be used to retrieve the report using \code{\link{file_report}}.
#' 
#' @param hash File hash (MD5, SHA1, or SHA256) or file ID. String. Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return list containing analysis details and ID
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
#' rescan_file(hash='99017f6eebbac24f351415dd410d522d')
#' }

rescan_file <- function(hash = NULL, ...) {

    # Validate hash using checkmate
    assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)

    res <- virustotal_POST(path = paste0("files/", hash, "/analyse"), ...)

    res
}
