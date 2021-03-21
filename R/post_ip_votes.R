#' Add a comment to an IP address
#'
#' Retrieves report on a given domain, including passive DNS, urls detected by at least one url scanner. 
#' Gives category of the domain from bitdefender.
#' 
#' @param ip IP address. String. Required.  
#' @param vote vote. String. Required.  
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
#' post_ip_comments("64.233.160.0", comment = "test")
#' }

post_ip_comments <- function(ip = NULL, comment = NULL, limit = NULL, ...) {

    if (!is.character(ip)) {
        stop("Must specify an IP address.\n")
    }

	comment = list("type" = "vote", "attributes" = list("text" = comment))

    res   <- virustotal_POST(path = paste0("ip/", domain, "/comments",
                                             query = list(limit = limit), ...)

    res
}
