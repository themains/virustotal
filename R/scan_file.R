#' Submit a file for scanning
#'
#' Uploads a file to VirusTotal for malware analysis using the v3 API.
#' Files larger than 32 MiB use a single-use upload URL; the maximum accepted
#' size is 650 MiB (one MiB is \eqn{1024^2} bytes). The final upload to a
#' single-use URL is not automatically retried. Retrieve the returned analysis
#' ID with \code{\link{get_analysis}}.
#'
#' @param file_path Required; Path to the file to be scanned
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}
#'
#' @return A \code{virustotal_file_scan} object with analysis ID and links
#'
#' @export
#' @family scanning functions
#'
#' @references \url{https://docs.virustotal.com/reference/files-scan}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{file_report}} for retrieving scan results
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
  assert_character(file_path, len = 1, any.missing = FALSE)
  assert_file_exists(file_path, access = "r")

  file_size <- file.info(file_path)$size
  if (file_size > 650 * 1024 * 1024) {
    stop(virustotal_validation_error(
      message = "File size exceeds the 650 MiB upload limit",
      parameter = "file_path",
      value = file_size
    ))
  }

  tryCatch(
    {
      if (file_size > 32 * 1024^2) {
        upload <- get_file_upload_url(...)
        url <- if (is.list(upload)) upload$data else NULL
        res <- vt_upload_file(file_path, url, ...)
      } else {
        res <- virustotal_POST(
          path = "files",
          body = list(file = form_file(file_path)),
          encode = "multipart",
          ...
        )
      }

      # Return structured response
      virustotal_file_scan(res)
    },
    error = function(e) {
      if (!inherits(e, "virustotal_error")) {
        stop(virustotal_error(
          message = paste("Failed to upload file:", e$message),
          response = NULL
        ))
      }
      stop(e)
    }
  )
}

vt_upload_file <- function(file_path, url, key = vt_key(), ...) {
  parsed <- if (checkmate::test_string(url, min.chars = 1)) {
    tryCatch(url_parse(url), error = function(e) NULL)
  }
  if (identical(parsed$scheme, "http") &&
        identical(parsed$hostname, url_parse(vt_base_url)$hostname)) {
    url <- httr2::url_modify(url, scheme = "https")
    parsed <- url_parse(url)
  }
  if (is.null(parsed) || !identical(parsed$scheme, "https") ||
        !checkmate::test_string(parsed$hostname, min.chars = 1) ||
        !is.null(parsed$username) || !is.null(parsed$password) ||
        !is.null(parsed$fragment)) {
    stop(virustotal_error("VirusTotal returned an invalid HTTPS upload URL."))
  }

  req <- httr2::req_url(vt_request("files", key), url)
  req <- req_body_multipart(req, file = form_file(file_path))
  req <- req_retry(req, max_tries = 1)
  req <- httr2::req_options(req, followlocation = FALSE)
  vt_body_json(vt_perform(req))
}
