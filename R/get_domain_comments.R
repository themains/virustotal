#' Retrieve comments for an Internet domain
#'
#' 
#' @param domain domain name. String. Required.
#' @param limit  Number of entries. Integer. Optional.  Default is 10.  
#' @param cursor String. Optional.  
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return named list with the following possible items: 
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
#' get_domain_comments("http://www.google.com")
#' get_domain_comments("http://www.goodsfwrfw.com") # Domain not found
#' }

get_domain_comments <- function(domain = NULL, limit = limit, cursor = cursor, ...) {

    if (!is.character(domain)) {
        stop("Must specify domain.\n")
    }

    domain <- gsub("^http://|^https://", "", domain)

    res   <- virustotal_GET(path = paste0("domains/", domain, "/comments"),
                                             query = list(limit = limit, cursor = cursor), ...)

    res
}
