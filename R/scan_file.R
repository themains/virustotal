#' Submit a file for scanning
#'
#' Uploads a file to VirusTotal for malware analysis using the v3 API.
#' 
#' @param file_path Required; Path to the file to be scanned
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}
#' 
#' @return A \code{virustotal_file_scan} object containing scan submission results
#'   with analysis ID and links for tracking the scan progress
#'  
#' @export
#' @family scanning functions
#' 
#' @references \url{https://docs.virustotal.com/reference/files-scan}
#' 
#' @seealso \code{\link{set_key}} for setting the API key, \code{\link{file_report}} for retrieving scan results
#'
#' @examples \dontrun{
#' # Set API key first
#' set_key('your_api_key_here')
#' 
#' # Scan a file
#' result <- scan_file(file_path = 'suspicious_file.exe')
#' print(result)
#' }

scan_file <- function(file_path, ...) {
  # Input validation using checkmate
  checkmate::assert_character(file_path, len = 1, any.missing = FALSE)
  checkmate::assert_file_exists(file_path, access = "r")
  
  # Check file size (VirusTotal has a 650MB limit for public API)
  file_size <- file.info(file_path)$size
  if (file_size > 650 * 1024 * 1024) {
    stop(virustotal_validation_error(
      message = "File size exceeds 650MB limit for public API",
      parameter = "file_path",
      value = paste(round(file_size / 1024 / 1024, 2), "MB")
    ))
  }

  tryCatch({
    res <- virustotal_POST(
      path = "files", 
      body = list(file = httr::upload_file(file_path)),
      ...
    )
    
    # Return structured response
    virustotal_file_scan(res)
  }, error = function(e) {
    if (!inherits(e, "virustotal_error")) {
      stop(virustotal_error(
        message = paste("Failed to upload file:", e$message),
        response = NULL
      ))
    }
    stop(e)
  })
}
