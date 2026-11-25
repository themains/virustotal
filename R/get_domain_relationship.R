#' Retrieve related object IDs for an Internet domain
#'
#' @inheritParams domain_report
#' @param limit  Number of entries. Integer. Optional.  Default is 10.
#' @param cursor String. Optional.
#' @param relationship A VirusTotal relationship name such as `subdomains`.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return A list containing the IDs and types of the related objects.
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
#' get_domain_relationship("https://www.google.com")
#' get_domain_relationship("https://www.example.com") # Domain not found
#' }
get_domain_relationship <- function(domain = NULL, relationship = "subdomains",
                                    limit = NULL, cursor = NULL, ...) {
  domain <- sanitize_domain(domain)
  validate_relationship(relationship)

  res <- virustotal_GET(
    path = paste0("domains/", domain, "/relationships/", relationship),
    query = list(limit = limit, cursor = cursor), ...
  )

  res
}
