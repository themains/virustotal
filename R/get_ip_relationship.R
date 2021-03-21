#' Retrieve related objects to an IP Address
#'
#' 
#' @param ip IP address. String. Required.   
#' @param relationship domain name. String. Required. Default is \code{subdomains}. 
#' For all the options see \link{https://developers.virustotal.com/v3.0/reference#domains-relationships}
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return named list
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
#' get_ip_relationship("64.233.160.0")
#' }

get_ip_relationship <- function(ip = NULL, relationship = "subdomains", limit = NULL, cursor = NULL, ...) {

    if (!is.character(domain)) {
        stop("Must specify domain.\n")
    }

    res   <- virustotal_GET(path = paste0("ip/", ip, "/relationship"),
                                             query = list(limit = limit, cursor = cursor), ...)

    res
}
