#' Retrieve votes for an Internet domain
#'
#'
#' @inheritParams domain_report
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
#' get_domain_votes("http://www.google.com")
#' get_domain_votes("https://www.example.com") # Domain not found
#' }
get_domain_votes <- function(domain = NULL, limit = NULL, cursor = NULL, ...) {
  domain <- sanitize_domain(domain)

  res <- virustotal_GET(
    path = paste0("domains/", domain, "/votes"),
    query = list(limit = limit, cursor = cursor), ...
  )

  res
}
