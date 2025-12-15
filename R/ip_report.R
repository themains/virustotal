#' Get IP Address Report
#' 
#' Retrieves comprehensive analysis report for an IP address, including 
#' geolocation, ASN information, DNS resolutions, and detected URLs.
#'
#' @param ip a valid IPv4 or IPv6 address; String; Required 
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return list containing IP analysis results including geolocation,
#' ASN information, DNS resolutions, detected URLs, and threat intelligence
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
#' ip_report(ip="8.8.8.8")
#' ip_report(ip="2001:4860:4860::8888")  # IPv6 example
#' }

ip_report <- function(ip = NULL, ...) {
    # Input validation first (before API key for proper test precedence)
    assert_character(ip, len = 1, any.missing = FALSE, min.chars = 1)
    
    # Check API key after basic validation
    if (identical(Sys.getenv("VirustotalToken"), "")) {
        stop(virustotal_auth_error(
            message = "Authentication failed. Please check your API key."
        ))
    }

    res <- virustotal_GET(path = paste0("ip_addresses/", ip), ...)

    res
}
