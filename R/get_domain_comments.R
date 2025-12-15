#' Retrieve comments for an Internet domain
#'
#'
#' @param domain domain name. String. Required.
#' @param limit  Number of entries. Integer. Optional.  Default is 10.
#' @param cursor String. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return list containing domain comment data including comment text, authors, dates,
#' and any associated metadata from the VirusTotal v3.0 API
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
#' get_domain_comments("http://www.google.com")
#' get_domain_comments("http://www.goodsfwrfw.com") # Domain not found
#' }

get_domain_comments <- function(domain = NULL, limit = limit, cursor = cursor, ...) {

    assert_character(domain, len = 1, any.missing = FALSE, min.chars = 1)

    domain <- gsub("^http://|^https://", "", domain)

    res   <- virustotal_GET(path = paste0("domains/", domain, "/comments"),
                                             query = list(limit = limit, cursor = cursor), ...)

    res
}
