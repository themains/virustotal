#' Retrieve related objects to an Internet domain
#'
#' @param domain domain name. String. Required. 
#' @param limit  Number of entries. Integer. Optional.  Default is 10.  
#' @param cursor String. Optional.
#' @param relationship relationship name. String. Required. Default is \code{subdomains}. 
#' For all the options see \url{https://developers.virustotal.com/v3.0/reference#domains-relationships}
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return named list
#'   
#' @export
#' 
#' @references \url{https://developers.virustotal.com/v2.0/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key
#' 
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#'    
#' get_domain_relationship("https://www.google.com")
#' get_domain_relationship("https://www.goodsfwrfw.com") # Domain not found
#' }

get_domain_relationship <- function(domain = NULL, relationship = "subdomains", limit = NULL, cursor = NULL, ...) {

    if (!is.character(domain)) {
        stop("Must specify domain.\n")
    }

    domain <- gsub("^http://|^https://", "", domain)

    res   <- virustotal_GET(path = paste0("domains/", domain, "/relationships/", relationship),
                                             query = list(limit = limit, cursor = cursor), ...)

    res
}
