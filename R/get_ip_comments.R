#' Retrieve comments for an IP address
#'
#' Retrieves report on a given domain, including passive DNS, urls detected by at least one url scanner. 
#' Gives category of the domain from bitdefender.
#' 
#' @param domain domain name. String. Required.  
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return named list
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
#' domains("http://www.google.com")
#' domains("http://www.goodsfwrfw.com") # Domain not found
#' }

get_ip_comments <- function(ip = NULL, limit = NULL, ...) {

    if (!is.character(ip)) {
        stop("Must specify an IP address.\n")
    }

    res   <- virustotal_GET(path = paste0("ip/", domain, "/comments"),
                                             query = list(limit = limit), ...)

    res
}
