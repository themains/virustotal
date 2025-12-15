#' Get File Scan Report
#'
#' Retrieves detailed analysis results for a file from VirusTotal using the v3 API.
#' 
#' @param hash File hash (MD5, SHA1, or SHA256) or analysis ID
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}
#' 
#' @return A \code{virustotal_file_report} object containing file analysis results
#'   including antivirus scans, file metadata, and threat detection information
#'  
#' @export
#' @family file operations
#' 
#' @references \url{https://docs.virustotal.com/reference/files}
#' 
#' @seealso \code{\link{set_key}} for setting the API key, \code{\link{scan_file}} for submitting files
#' 
#' @examples \dontrun{
#' # Set API key first
#' set_key('your_api_key_here')
#' 
#' # Get file report using hash
#' report <- file_report(hash = '99017f6eebbac24f351415dd410d522d')
#' print(report)
#' summary(report)
#' 
#' # Work with the rich nested structure returned by v3 API
#' print(report$data$attributes$last_analysis_stats)
#' }

file_report <- function(hash, ...) {
  # Handle missing argument first
  if (missing(hash)) {
    stop(virustotal_validation_error(
      message = "Hash must be provided",
      parameter = "hash", 
      value = "missing"
    ))
  }
  
  # Handle NULL and type validation before API key (for proper test precedence)
  if (is.null(hash)) {
    stop(virustotal_validation_error(
      message = "Hash cannot be NULL",
      parameter = "hash",
      value = "NULL"
    ))
  }
  
  # Input validation
  tryCatch({
    assert_character(hash, len = 1, any.missing = FALSE, 
                                 min.chars = 1)
  }, error = function(e) {
    stop(virustotal_validation_error(
      message = "Hash must be a non-empty character string",
      parameter = "hash",
      value = if (is.null(hash)) "NULL" else class(hash)[1]
    ))
  })
  
  # Check API key after basic validation
  if (identical(Sys.getenv("VirustotalToken"), "")) {
    stop(virustotal_auth_error(
      message = "Authentication failed. Please check your API key."
    ))
  }

  # Validate hash format (basic check)
  # MD5, SHA1, SHA256, or analysis ID lengths
  if (!grepl("^[a-fA-F0-9]+$", hash) ||
      (!nchar(hash) %in% c(32, 40, 64, 40))) {
    stop(virustotal_validation_error(
      message = paste("Hash must be a valid MD5 (32), SHA1 (40),",
                      "SHA256 (64), or analysis ID"),
      parameter = "hash",
      value = hash
    ))
  }

  tryCatch({
    res <- virustotal_GET(path = paste0("files/", hash), ...)

    # Return structured response
    virustotal_file_report(res)
  }, error = function(e) {
    if (!inherits(e, "virustotal_error")) {
      stop(virustotal_error(
        message = paste("Failed to retrieve file report:", e$message),
        response = NULL
      ))
    }
    stop(e)
  })
}
