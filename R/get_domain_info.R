#' Retrieve information about an Internet domain
#'
#' 
#' @param domain domain name. String. Required.  
#' @param limit  Number of entries. Integer. Optional.  Default is 10.  
#' @param cursor String. Optional.  
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
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
#' get_domain_info("http://www.google.com")
#' get_domain_info("http://www.goodsfwrfw.com") # Domain not found
#' }

get_domain_info <- function(domain = NULL,  limit = NULL, cursor = NULL, ...) {

    if (!is.character(domain)) {
        stop("Must specify domain.\n")
    }

    domain <- gsub("^http://|^https://", "", domain)

    res   <- virustotal_GET(path = paste0("domains/", domain),
                            query = list(limit = limit, cursor = cursor), ...)

    res
}
