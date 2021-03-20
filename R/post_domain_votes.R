#' Add a vote for a hostname or domain
#'
#' 
#' @param domain domain name. String. Required.
#' @param domain vote. String. Required.  
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
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
#' post_domain_votes("http://www.google.com")
#' post_domain_votes("http://www.goodsfwrfw.com") # Domain not found
#' }

post_domain_votes <- function(domain = NULL, limit = NULL, cursor = NULL, vote = NULL, ...) {

    if (!is.character(domain)) {
        stop("Must specify domain.\n")
    }

	vote = list("type" = "vote", "attributes" = list("verdict" = vote))

    domain <- gsub("^http://", "", domain)

    res   <- virustotal_POST(path = paste0("domains/", domain, "/votes"),
                                             query = list(limit = limit, cursor = cursor, vote = vote), ...)

    res
}
