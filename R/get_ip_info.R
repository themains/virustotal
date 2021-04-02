#' Retrieve information about an IP address
#'
#' Retrieves report on a given domain, including passive DNS, urls detected by at least one url scanner. 
#' Gives category of the domain from bitdefender.
#' 
#' @param ip IP address. String. Required.
#' @param limit  Number of entries. Integer. Optional.  Default is 10.  
#' @param cursor String. Optional.
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
#' get_ip_info("64.233.160.0")
#' }

get_ip_info <- function(ip = NULL, limit = NULL, cursor = NULL, ...) {

    if (!is.character(ip)) {
        stop("Must specify an IP address.\n")
    }

    res   <- virustotal_GET(path = paste0("ip_addresses/", ip),
                                             query = list(limit = limit, cursor = cursor), ...)

    res
}
