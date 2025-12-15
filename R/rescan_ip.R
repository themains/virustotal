#' Request rescan of an IP address
#' 
#' Request a new analysis of an IP address already present in VirusTotal's database.
#' Returns an analysis ID that can be used to retrieve the report using \code{\link{ip_report}}.
#' 
#' @param ip IP address to rescan (IPv4 or IPv6). String. Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return list containing analysis details and ID
#' 
#' @export
#' 
#' @references \url{https://docs.virustotal.com/reference}
#' 
#' @seealso \code{\link{set_key}} for setting the API key, \code{\link{ip_report}} for getting reports
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
  
  if (is.null(ip) || !is.character(ip) || nchar(ip) == 0) {
    stop("Must specify a valid IP address.\n")
  }
  
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

# Helper function to validate IP addresses
is_valid_ip <- function(ip) {
  # Simple regex for IPv4
  ipv4_pattern <- "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
  
  # Simple regex for IPv6 (basic validation)
  ipv6_pattern <- "^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){1,6}:$|^::[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$"
  
  grepl(ipv4_pattern, ip) || grepl(ipv6_pattern, ip)
}
