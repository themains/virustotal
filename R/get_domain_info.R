#' Retrieve information about an Internet domain
#'
#'
#' @inheritParams domain_report
#' @param key API key for this request. Defaults to the configured key.
#' @param \dots Unused. Extra arguments trigger a warning.
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
#' get_domain_info("https://www.example.com") # Domain not found
#' }
get_domain_info <- function(domain = NULL, ..., key = vt_key()) {
  domain <- sanitize_domain(domain)

  warn_ignored_dots(...)
  virustotal_GET(paste0("domains/", domain), key = key)
}
