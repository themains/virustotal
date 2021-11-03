#' Retrieve votes for an IP address
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
#' @references \url{https://developers.virustotal.com/v2.0/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key
#' 
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#'    
#' get_ip_votes("64.233.160.0")
#' }

get_ip_votes <- function(ip = NULL, limit = NULL, cursor = NULL, ...) {

    if (!is.character(ip)) {
        stop("Must specify an IP address.\n")
    }

    res   <- virustotal_GET(path = paste0("ip_addresses/", ip, "/votes"),
                             query = list(limit = limit, cursor = cursor), ...)

    res
}
