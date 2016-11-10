#' Get Domain Report
#'
#' Retrieves report on a given domain, including passive DNS, urls detected by at least one url scanner. 
#' Gives category of the domain from \url{http://www.bitdefender.com/}
#' 
#' @param domain domain name. String. Required.  
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return names list with the following items: 
#' \code{`BitDefender category`, undetected_referrer_samples, whois_timestamp,
#' detected_downloaded_samples, detected_referrer_samples, `Webutation domain info`, `Alexa category`, undetected_downloaded_samples,
#' resolutions, detected_communicating_samples, `Opera domain info`, `TrendMicro category`, categories, domain_siblings, 
#' `BitDefender domain info`, whois, `Alexa domain info`, response_code, verbose_msg, `Websense ThreatSeeker category`, subdomains,
#' `WOT domain info`, detected_urls, `Alexa rank`, undetected_communicating_samples, `Dr.Web category`, pcaps}
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
#' domain_report("http://www.google.com")
#' }

domain_report <- function(domain = NULL, ...) {

    if (!is.character(domain)) {
        stop("Must specify domain")
    }

    domain = gsub("^http://", "", domain)

    res   <- virustotal_GET(path="domain/report", query = list(domain = domain), ...)

    res
}




