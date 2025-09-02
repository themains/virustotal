#' Get Domain Report
#'
#' Retrieves comprehensive analysis report for a given domain, including 
#' WHOIS information, DNS resolutions, detected URLs, and threat intelligence data.
#' 
#' @param domain domain name. String. Required.  
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return list containing domain analysis results including WHOIS data,
#' DNS resolutions, detected URLs, categories, and threat intelligence
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
#' domain_report("google.com")
#' domain_report("example.com")
#' }

domain_report <- function(domain = NULL, ...) {

    if (is.null(domain) || !is.character(domain) || nchar(domain) == 0) {
        stop("Must specify a valid domain name.\n")
    }

    # Clean up domain (remove protocol if present)
    domain <- gsub("^https?://", "", domain)
    domain <- gsub("^www\\.", "", domain)
    domain <- gsub("/.*$", "", domain)  # Remove any path

    res <- virustotal_GET(path = paste0("domains/", domain), ...)

    res
}
