#' Add a vote for a hostname or domain
#'
#' 
#' @param domain domain name. String. Required.
#' @param vote vote. String. Required. 
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return named list 
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
#' post_domain_votes("http://google.com", vote = "malicious")
#' }

post_domain_votes <- function(domain = NULL, vote = NULL,...) {

    if (!is.character(domain)) {
        stop("Must specify domain.\n")
    }

    domain <- gsub("^http://|^https://", "", domain)

	vote_r = list("data" = list("type" = "vote", "attributes" = list("verdict" = vote)))

    res   <- virustotal_POST(path = paste0("domains/", domain, "/votes"),
    	                     body  = vote_r, ...)

    res
}
