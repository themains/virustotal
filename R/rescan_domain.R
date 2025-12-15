#' Request rescan of a domain
#'
#' Request a new analysis of a domain already present in VirusTotal's database.
#' Returns an analysis ID that can be used to retrieve the report using \code{\link{domain_report}}.
#'
#' @param domain Domain name to rescan. String. Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#'
#' @return list containing analysis details and ID
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key, \code{\link{domain_report}} for getting reports
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' # Request rescan of a domain
#' rescan_domain("google.com")
#' }

rescan_domain <- function(domain = NULL, ...) {

  assert_character(domain, len = 1, any.missing = FALSE, min.chars = 1)

  # Validate and clean domain input
  domain <- validate_input(domain)

  # Clean domain (remove protocol, www, paths)
  domain <- gsub("^https?://", "", domain)
  domain <- gsub("^www\\.", "", domain)
  domain <- gsub("/.*$", "", domain)

  res <- virustotal_POST(path = paste0("domains/", domain, "/rescan"), ...)

  # Return structured response
  structure(res, class = c("virustotal_response", "list"))
}
