#' Retrieve information about an IP address
#'
#' Retrieves report on a given IP address.
#'
#' @param ip IP address. Required.
#' @param key API key for this request. Defaults to the configured key.
#' @param \dots Unused. Extra arguments trigger a warning.
#'
#' @return named list
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
#' get_ip_info("64.233.160.0")
#' }
get_ip_info <- function(ip = NULL, ..., key = vt_key()) {
  ip <- sanitize_ip(ip)

  warn_ignored_dots(...)
  virustotal_GET(paste0("ip_addresses/", ip), key = key)
}
