#' Request rescan of an IP address
#'
#' Request a new analysis of an IP address already in VirusTotal's database.
#' Returns an analysis ID for use with \code{\link{ip_report}}.
#'
#' @param ip IP address to rescan (IPv4 or IPv6). Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#'
#' @return list containing analysis details and ID
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{ip_report}} for getting reports
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' # Request rescan of an IPv4 address
#' rescan_ip("8.8.8.8")
#'
#' # Request rescan of an IPv6 address
#' rescan_ip("2001:4860:4860::8888")
#' }
rescan_ip <- function(ip = NULL, ...) {
  assert_character(ip, len = 1, any.missing = FALSE, min.chars = 1)

  # Validate IP address format
  ip <- validate_input(ip)

  # Basic IP validation (IPv4 and IPv6)
  if (!is_valid_ip(ip)) {
    stop("Invalid IP address format. Must be a valid IPv4 or IPv6 address.\n")
  }

  res <- virustotal_POST(path = paste0("ip_addresses/", ip, "/analyse"), ...)

  # Return structured response
  structure(res, class = c("virustotal_response", "list"))
}

is_valid_ip <- function(ip) {
  ipv4 <- "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
  ipv4 <- paste0(ipv4, "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

  ipv6 <- "^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$"

  grepl(ipv4, ip) || grepl(ipv6, ip)
}
