#' Retrieve comments for an IP address
#' 
#' @param ip IP Address. String. Required.  
#' @param limit  Number of entries. Integer. Optional.  Default is 10.  
#' @param cursor String. Optional.
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
#' get_ip_comments("64.233.160.0")
#' }

get_ip_comments <- function(ip = NULL, limit = NULL, cursor = NULL, ...) {

    if (!is.character(ip)) {
        stop("Must specify an IP address.\n")
    }

    res   <- virustotal_GET(path = paste0("ip_addresses/", ip, "/comments"),
                                             query = list(limit = limit, cursor = cursor), ...)

    res
}
