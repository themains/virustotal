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
  .virustotal_state$requests <- numeric(0)
  .virustotal_state$window_size <- 60  # 60 seconds
  .virustotal_state$max_requests <- 4
  .virustotal_state$initialized <- TRUE
}

#' Check if rate limiting is properly initialized
#' 
#' @keywords internal
is_rate_limit_initialized <- function() {
  !is.null(.virustotal_state$initialized) && 
    !is.null(.virustotal_state$requests) &&
    !is.null(.virustotal_state$window_size) &&
    !is.null(.virustotal_state$max_requests)
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
  # Initialize if needed - check all components
  if (!is_rate_limit_initialized()) {
    init_rate_limit()
  }
  
  current_time <- as.numeric(Sys.time())
  window_size <- .virustotal_state$window_size
  if (is.null(window_size)) window_size <- 60  # fallback
  
  window_start <- current_time - window_size
  
  # Clean old requests outside the window - handle empty case
  requests <- .virustotal_state$requests
  if (is.null(requests)) requests <- numeric(0)
  
  if (length(requests) > 0) {
    active_requests <- requests[requests > window_start]
  } else {
    active_requests <- numeric(0)
  }
  .virustotal_state$requests <- active_requests
  
  # Check if we're at the limit - add NULL safety
  max_requests <- .virustotal_state$max_requests
  if (is.null(max_requests)) max_requests <- 4  # fallback
  
  if (length(.virustotal_state$requests) >= max_requests || force_wait) {
    if (length(.virustotal_state$requests) > 0) {
      # Calculate wait time until oldest request expires - use safe variables
      oldest_request <- min(active_requests)
      wait_time <- max(0, window_size - (current_time - oldest_request))
      
      if (wait_time > 0) {
        message(sprintf("Rate limit reached. Waiting %.1f seconds...", wait_time))
        Sys.sleep(wait_time + 0.1)  # Add small buffer
        
        # Update current time and clean requests again
        current_time <- as.numeric(Sys.time())
        window_start <- current_time - window_size
        
        # Re-clean with defensive programming
        requests_after_wait <- .virustotal_state$requests
        if (!is.null(requests_after_wait) && length(requests_after_wait) > 0) {
          active_requests_after_wait <- requests_after_wait[requests_after_wait > window_start]
        } else {
          active_requests_after_wait <- numeric(0)
        }
        .virustotal_state$requests <- active_requests_after_wait
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
  # Ensure complete initialization
  if (!is_rate_limit_initialized()) {
    init_rate_limit()
  }
  
  current_time <- as.numeric(Sys.time())
  
  # Get values with fallbacks
  window_size <- .virustotal_state$window_size
  if (is.null(window_size)) window_size <- 60
  
  max_requests <- .virustotal_state$max_requests  
  if (is.null(max_requests)) max_requests <- 4
  
  requests <- .virustotal_state$requests
  if (is.null(requests)) requests <- numeric(0)
  
  window_start <- current_time - window_size
  
  # Clean old requests - handle empty case
  if (length(requests) > 0) {
    active_requests <- requests[requests > window_start]
  } else {
    active_requests <- numeric(0)
  }
  
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

#' Reset rate limiting state
#' 
#' Clears all rate limiting history. Useful for testing.
#' 
#' @export
#' @family rate limiting
reset_rate_limit <- function() {
  init_rate_limit()
  message("Rate limiting state reset.")
  invisible(TRUE)
}
