#' Get Domain Report
#'
#' Retrieves comprehensive analysis report for a given domain, including
#' WHOIS information, DNS resolutions, detected URLs, and threat intelligence
#' data.
#'
#' @param domain Domain name (character string). Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}
#'
#' @return A \code{virustotal_domain_report} object containing domain analysis
#'   results including WHOIS data, DNS resolutions, detected URLs, categories,
#'   and threat intelligence
#'
#' @export
#' @family domain operations
#'
#' @references \url{https://docs.virustotal.com/reference/domains}
#'
#' @seealso \code{\link{set_key}} for setting the API key
#'
#' @examples \dontrun{
#' # Set API key first
#' set_key('your_api_key_here')
#'
#' # Get domain reports
#' report1 <- domain_report("google.com")
#' report2 <- domain_report("https://www.example.com/path")
#'
#' print(report1)
#' summary(report1)
#' }

domain_report <- function(domain, ...) {
  # Handle missing argument
  if (missing(domain)) {
    stop(virustotal_validation_error(
      message = "Domain must be provided",
      parameter = "domain",
      value = "missing"
    ))
  }
  
  # Handle NULL before checkmate validation
  if (is.null(domain)) {
    stop(virustotal_validation_error(
      message = "Domain cannot be NULL",
      parameter = "domain",
      value = "NULL"
    ))
  }
  
  # Input validation with proper error handling (before API key for tests)
  tryCatch({
    assert_character(domain, len = 1, any.missing = FALSE,
                                 min.chars = 1)
  }, error = function(e) {
    stop(virustotal_validation_error(
      message = "Domain must be a non-empty character string",
      parameter = "domain",
      value = if (is.null(domain)) "NULL" else class(domain)[1]
    ))
  })

  # Clean up domain (remove protocol, www, and paths for security) before validation
  domain_clean <- domain
  domain_clean <- gsub("^https?://", "", domain_clean)
  domain_clean <- gsub("^www\\.", "", domain_clean)
  domain_clean <- gsub("/.*$", "", domain_clean)  # Remove any path
  domain_clean <- gsub("\\.$", "", domain_clean)  # Remove trailing dot

  # Basic domain validation (before API key check for test precedence)
  if (!grepl("^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$", domain_clean) ||
        grepl("\\.\\.", domain_clean)) {
    stop(virustotal_validation_error(
      message = "Invalid domain format",
      parameter = "domain",
      value = domain
    ))
  }
  
  # Check API key after all validation
  if (identical(Sys.getenv("VirustotalToken"), "")) {
    stop(virustotal_auth_error(
      message = "Authentication failed. Please check your API key."
    ))
  }

  tryCatch({
    res <- virustotal_GET(path = paste0("domains/", domain_clean), ...)

    # Return structured response
    virustotal_domain_report(res)
  }, error = function(e) {
    if (!inherits(e, "virustotal_error")) {
      stop(virustotal_error(
        message = paste("Failed to retrieve domain report:", e$message),
        response = NULL
      ))
    }
    stop(e)
  })
}
