#' Request rescan of a domain
#'
#' Request a new analysis of a domain already in VirusTotal's database.
#' Returns an analysis ID for use with \code{\link{get_analysis}}.
#'
#' @inheritParams domain_report
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#'
#' @return list containing analysis details and ID
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{domain_report}} for getting reports
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' # Request rescan of a domain
#' rescan_domain("google.com")
#' }
rescan_domain <- function(domain = NULL, ...) {
  domain <- sanitize_domain(domain)

  res <- virustotal_POST(path = paste0("domains/", domain, "/analyse"), ...)

  # Return structured response
  structure(res, class = c("virustotal_response", "list"))
}
