#' Retrieve information about an IP address
#'
#' Retrieves report on a given IP address.
#'
#' @param ip IP address. Required.
#' @param limit Number of entries. Optional.
#' @param cursor String. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
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

get_ip_info <- function(ip = NULL, limit = NULL, cursor = NULL, ...) {

    assert_character(ip, len = 1, any.missing = FALSE, min.chars = 1)

    res <- virustotal_GET(path = paste0("ip_addresses/", ip),
                          query = list(limit = limit, cursor = cursor), ...)

    res
}
