#' Add a comment to an Internet domain
#'
#' 
#' @param domain domain name. String. Required.  
#' @param comment vote. String. Required.  Any word starting with # in your comment's text will be considered a tag, and added to the comment's tag attribute.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return named list
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
#' post_domain_comments(domain = "https://google.com", comment = "Great!")
#' }

post_domain_comments <- function(domain = NULL, comment = NULL,...) {

    if (!is.character(domain)) {
        stop("Must specify domain.\n")
    }

    domain <- gsub("^http://|^https://", "", domain)

	comment_r = list("data" = list("type" = "comment", "attributes" = list("text" = comment)))

    res   <- virustotal_POST(path = paste0("domains/", domain, "/comments"),
    	                     body  = comment_r,...)

    res
}
