#' Get IP Report
#' 
#' Get passive DNS data and URLs detected by URL scanners 
#'
#' @param ip a valid IPv4 address in dotted quad notation; String; Required 
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return named list with the following potential items: 
#' \code{undetected_referrer_samples, detected_downloaded_samples, detected_referrer_samples, 
#' undetected_downloaded_samples, detected_urls, undetected_downloaded_samples, response_code, as_owner, verbose_msg, country, 
#' undetected_referrer_samples, detected_communicating_samples, resolutions, undetected_communicating_samples, asn}
#'  
#' @export
#' 
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' 
#' @seealso \code{\link{set_key}} for setting the API key
#'
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' ip_report(ip="8.8.8.8")
#' }

ip_report <- function(ip = NULL, ...) {

    if (!is.character(ip)) {
        stop("Must specify a valid IP.\n")
    }

    params <- list(ip = ip)

    res   <- virustotal_GET(path="ip-address/report", query = params, ...)

    res
}
