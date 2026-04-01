#' Request rescan of a URL
#'
#' Request a new analysis of a URL already present in VirusTotal's database.
#' Returns an analysis ID for use with \code{\link{url_report}}.
#'
#' @param url_id URL or URL ID (base64 encoded URL without padding). Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#'
#' @return list containing analysis details and ID
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{url_report}} for getting reports
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' # Request rescan using URL
#' rescan_url("http://www.google.com")
#'
#' # Request rescan using URL ID
#' rescan_url("687474703a2f2f7777772e676f6f676c652e636f6d2f")
#' }

rescan_url <- function(url_id = NULL, ...) {

  assert_character(url_id, len = 1, any.missing = FALSE, min.chars = 1)

  url_id <- validate_input(url_id)

  encoded_url_id <- URLencode(url_id, reserved = TRUE)

  path <- paste0("urls/", encoded_url_id, "/analyse")
  res <- virustotal_POST(path = path, ...)

  structure(res, class = c("virustotal_response", "list"))
}
