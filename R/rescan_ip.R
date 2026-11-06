#' Request rescan of an IP address
#'
#' Request a new analysis of an IP address already in VirusTotal's database.
#' Returns an analysis ID for use with \code{\link{get_analysis}}.
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
  ip <- sanitize_ip(ip)

  res <- virustotal_POST(path = paste0("ip_addresses/", ip, "/analyse"), ...)

  # Return structured response
  structure(res, class = c("virustotal_response", "list"))
}
