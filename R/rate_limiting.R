#' Rate Limiting for VirusTotal API
#'
#' @description
#' Pacing is enforced by \code{httr2::req_throttle()} inside the shared
#' request builder (see \code{vt_request}), tunable via
#' \code{options(virustotal.requests_per_minute=)} and switchable via
#' \code{options(virustotal.throttle=)}. What lives here is a passive log of
#' request times, kept so \code{virustotal_info()} can report usage against
#' the public API's 4-per-minute allowance.
#'
#' @name rate-limiting
#' @keywords internal
#' @family rate limiting
NULL

.virustotal_state <- new.env(parent = emptyenv())

#' Initialize the request log
#'
#' @keywords internal
init_rate_limit <- function() {
  .virustotal_state$requests <- numeric(0)
  .virustotal_state$window_size <- 60
  .virustotal_state$max_requests <- 4
  .virustotal_state$initialized <- TRUE
}

#' Is the request log initialized?
#'
#' @keywords internal
is_rate_limit_initialized <- function() {
  !is.null(.virustotal_state$initialized) &&
    !is.null(.virustotal_state$requests) &&
    !is.null(.virustotal_state$window_size) &&
    !is.null(.virustotal_state$max_requests)
}

#' Record a performed request
#'
#' Appends a timestamp to the log. Called after each successful
#' \code{req_perform()}; enforcement is httr2's job, not this function's.
#'
#' @return Invisible TRUE
#' @keywords internal
#' @family rate limiting
record_request <- function() {
  if (!is_rate_limit_initialized()) {
    init_rate_limit()
  }
  .virustotal_state$requests <- c(
    .virustotal_state$requests, as.numeric(Sys.time())
  )
  invisible(TRUE)
}

#' Get current rate limit status
#'
#' @return List with current status information
#' @keywords internal
#' @family rate limiting
get_rate_limit_status <- function() {
  if (!is_rate_limit_initialized()) {
    init_rate_limit()
  }

  current_time <- as.numeric(Sys.time())

  window_size <- .virustotal_state$window_size %||% 60
  # Read the pace at call time: a premium key that set
  # virustotal.requests_per_minute = 1000 was otherwise reported against the
  # public allowance, printing things like "used 10/4, remaining -6".
  max_requests <- getOption(
    "virustotal.requests_per_minute", .virustotal_state$max_requests %||% 4
  )
  requests <- .virustotal_state$requests %||% numeric(0)

  window_start <- current_time - window_size
  active_requests <- requests[requests > window_start]

  list(
    requests_used = length(active_requests),
    max_requests = max_requests,
    window_size = window_size,
    requests_remaining = max_requests - length(active_requests),
    window_reset_time = if (length(active_requests) > 0) {
      min(active_requests) + window_size
    } else {
      current_time
    }
  )
}

#' Reset the request log
#'
#' Clears all recorded request times. Useful for testing.
#'
#' @keywords internal
#' @family rate limiting
reset_rate_limit <- function() {
  init_rate_limit()
  invisible(TRUE)
}
