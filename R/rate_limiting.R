#' Rate Limiting for VirusTotal API
#'
#' @description
#' Modern rate limiting implementation that properly manages API request limits.
#' VirusTotal public API allows 4 requests per minute.
#' 
#' @name rate-limiting
#' @family rate limiting
NULL

# Package-level environment for rate limiting state
.virustotal_state <- new.env(parent = emptyenv())

#' Initialize rate limiting state
#' 
#' @keywords internal
init_rate_limit <- function() {
  .virustotal_state$requests <- character(0)
  .virustotal_state$window_size <- 60  # 60 seconds
  .virustotal_state$max_requests <- 4
}

#' Modern rate limiting implementation
#' 
#' Uses a sliding window approach to track requests and enforce limits.
#' This replaces the old environment variable-based approach.
#' 
#' @param force_wait Logical. If TRUE, will wait even if under limit
#' @return Invisible TRUE
#' @keywords internal
#' @family rate limiting
rate_limit <- function(force_wait = FALSE) {
  # Initialize if needed
  if (is.null(.virustotal_state$requests)) {
    init_rate_limit()
  }
  
  current_time <- as.numeric(Sys.time())
  window_start <- current_time - .virustotal_state$window_size
  
  # Clean old requests outside the window
  .virustotal_state$requests <- .virustotal_state$requests[
    .virustotal_state$requests > window_start
  ]
  
  # Check if we're at the limit
  if (length(.virustotal_state$requests) >= .virustotal_state$max_requests || force_wait) {
    if (length(.virustotal_state$requests) > 0) {
      # Calculate wait time until oldest request expires
      oldest_request <- min(.virustotal_state$requests)
      wait_time <- max(0, .virustotal_state$window_size - (current_time - oldest_request))
      
      if (wait_time > 0) {
        message(sprintf("Rate limit reached. Waiting %.1f seconds...", wait_time))
        Sys.sleep(wait_time + 0.1)  # Add small buffer
        
        # Update current time and clean requests again
        current_time <- as.numeric(Sys.time())
        window_start <- current_time - .virustotal_state$window_size
        .virustotal_state$requests <- .virustotal_state$requests[
          .virustotal_state$requests > window_start
        ]
      }
    }
  }
  
  # Record this request
  .virustotal_state$requests <- c(.virustotal_state$requests, current_time)
  
  invisible(TRUE)
}

#' Get current rate limit status
#' 
#' @return List with current status information
#' @export
#' @family rate limiting
get_rate_limit_status <- function() {
  if (is.null(.virustotal_state$requests)) {
    init_rate_limit()
  }
  
  current_time <- as.numeric(Sys.time())
  window_start <- current_time - .virustotal_state$window_size
  
  # Clean old requests
  active_requests <- .virustotal_state$requests[.virustotal_state$requests > window_start]
  
  list(
    requests_used = length(active_requests),
    max_requests = .virustotal_state$max_requests,
    window_size = .virustotal_state$window_size,
    requests_remaining = .virustotal_state$max_requests - length(active_requests),
    window_reset_time = if (length(active_requests) > 0) {
      min(active_requests) + .virustotal_state$window_size
    } else {
      current_time
    }
  )
}

#' Reset rate limiting state
#' 
#' Clears all rate limiting history. Useful for testing.
#' 
#' @export
#' @family rate limiting
reset_rate_limit <- function() {
  .virustotal_state$requests <- character(0)
  message("Rate limiting state reset.")
  invisible(TRUE)
}
