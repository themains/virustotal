#' VirusTotal API Error Classes
#'
#' @description
#' Custom error classes for structured error handling in the virustotal package.
#' 
#' @name virustotal-errors
#' @keywords internal
#' @family error handling
NULL

#' Create a VirusTotal API error
#'
#' @param message Error message
#' @param status_code HTTP status code
#' @param response Full HTTP response object
#' @param call The calling function (automatically detected)
#'
#' @return An error object of class \code{virustotal_error}
#' @keywords internal
#' @export
#' @family error handling
virustotal_error <- function(message, status_code = NULL, response = NULL, call = sys.call(-1)) {
  structure(
    list(
      message = message,
      status_code = status_code,
      response = response,
      call = call
    ),
    class = c("virustotal_error", "error", "condition")
  )
}

#' Create a rate limit error
#'
#' @param message Error message
#' @param retry_after Number of seconds to wait before retry
#' @param call The calling function (automatically detected)
#'
#' @return An error object of class \code{virustotal_rate_limit_error}
#' @keywords internal
#' @export
#' @family error handling
virustotal_rate_limit_error <- function(message = "Rate limit exceeded", 
                                       retry_after = 60, 
                                       call = sys.call(-1)) {
  structure(
    list(
      message = message,
      retry_after = retry_after,
      call = call
    ),
    class = c("virustotal_rate_limit_error", "virustotal_error", "error", "condition")
  )
}

#' Create an authentication error
#'
#' @param message Error message
#' @param call The calling function (automatically detected)
#'
#' @return An error object of class \code{virustotal_auth_error}
#' @keywords internal
#' @export
#' @family error handling
virustotal_auth_error <- function(message = "Invalid or missing API key", 
                                 call = sys.call(-1)) {
  structure(
    list(
      message = message,
      call = call
    ),
    class = c("virustotal_auth_error", "virustotal_error", "error", "condition")
  )
}

#' Create a validation error
#'
#' @param message Error message
#' @param parameter The parameter that failed validation
#' @param value The invalid value
#' @param call The calling function (automatically detected)
#'
#' @return An error object of class \code{virustotal_validation_error}
#' @keywords internal
#' @export
#' @family error handling
virustotal_validation_error <- function(message, parameter = NULL, value = NULL, 
                                       call = sys.call(-1)) {
  structure(
    list(
      message = message,
      parameter = parameter,
      value = value,
      call = call
    ),
    class = c("virustotal_validation_error", "virustotal_error", "error", "condition")
  )
}

#' Print method for VirusTotal errors
#' 
#' @param x A virustotal_error object
#' @param ... Additional arguments (unused)
#' @keywords internal
print.virustotal_error <- function(x, ...) {
  cat("VirusTotal API Error: ", x$message, "\n", sep = "")
  if (!is.null(x$status_code)) {
    cat("HTTP Status Code: ", x$status_code, "\n", sep = "")
  }
  if (inherits(x, "virustotal_rate_limit_error") && !is.null(x$retry_after)) {
    cat("Retry after: ", x$retry_after, " seconds\n", sep = "")
  }
  if (!is.null(x$parameter)) {
    cat("Parameter: ", x$parameter, "\n", sep = "")
  }
  invisible(x)
}
