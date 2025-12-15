#' Utility Functions for VirusTotal Package
#'
#' @description
#' Helper functions and utilities for the VirusTotal package.
#' 
#' @name utilities
#' @family utilities
NULL

#' Check if running in a safe environment
#'
#' Verifies that the package is running in an appropriate environment
#' for security analysis work.
#' 
#' @return Logical indicating if environment is considered safe
#' @keywords internal
#' @family utilities
is_safe_environment <- function() {
  # Check if we're in an interactive session
  if (!interactive()) {
    warning("Running in non-interactive mode. Be cautious with file operations.")
  }
  
  # Check for common CI environments where we should be extra careful
  ci_vars <- c("CI", "GITHUB_ACTIONS", "TRAVIS", "APPVEYOR", "GITLAB_CI")
  if (any(Sys.getenv(ci_vars) != "")) {
    message("Detected CI environment. Some functions may be disabled for security.")
    return(FALSE)
  }
  
  return(TRUE)
}

#' Convert file size to human readable format
#'
#' @param size_bytes File size in bytes
#' @return Character string with human-readable size
#' @export
#' @family utilities
format_file_size <- function(size_bytes) {
  checkmate::assert_numeric(size_bytes, len = 1, lower = 0)
  
  units <- c("B", "KB", "MB", "GB", "TB")
  unit_index <- 1
  size <- size_bytes
  
  while (size >= 1024 && unit_index < length(units)) {
    size <- size / 1024
    unit_index <- unit_index + 1
  }
  
  sprintf("%.2f %s", size, units[unit_index])
}

#' Validate VirusTotal response structure
#'
#' Checks if a response from VirusTotal API has the expected structure.
#' 
#' @param response Response object from VirusTotal API
#' @return Logical indicating if response structure is valid
#' @keywords internal
#' @family utilities
validate_vt_response <- function(response) {
  if (!is.list(response)) {
    return(FALSE)
  }
  
  # Check for common VirusTotal response fields
  if (is.null(response$data)) {
    return(FALSE)
  }
  
  # Basic structure validation
  if (!is.list(response$data)) {
    return(FALSE)
  }
  
  return(TRUE)
}

#' Create a safe temporary directory for file operations
#'
#' Creates a temporary directory with restricted permissions for secure
#' file operations during malware analysis.
#' 
#' @return Path to the temporary directory
#' @export
#' @family utilities
create_safe_temp_dir <- function() {
  temp_dir <- tempfile(pattern = "virustotal_")
  dir.create(temp_dir, mode = "0700")  # Owner read/write/execute only
  
  # Set stricter permissions if on Unix-like system
  if (.Platform$OS.type == "unix") {
    Sys.chmod(temp_dir, mode = "0700")
  }
  
  message("Created secure temporary directory: ", temp_dir)
  return(temp_dir)
}

#' Clean up temporary files and directories
#'
#' Safely removes temporary files and directories created during
#' VirusTotal operations.
#' 
#' @param paths Character vector of file/directory paths to clean up
#' @return Logical indicating success
#' @export
#' @family utilities
cleanup_temp_files <- function(paths) {
  checkmate::assert_character(paths, any.missing = FALSE)
  
  success <- TRUE
  for (path in paths) {
    if (file.exists(path)) {
      tryCatch({
        if (file.info(path)$isdir) {
          unlink(path, recursive = TRUE, force = TRUE)
        } else {
          file.remove(path)
        }
        message("Cleaned up: ", path)
      }, error = function(e) {
        warning("Failed to clean up ", path, ": ", e$message)
        success <<- FALSE
      })
    }
  }
  
  return(success)
}

#' Get package version information
#'
#' @return Character string with package version
#' @export
#' @family utilities
virustotal_version <- function() {
  desc <- utils::packageDescription("virustotal")
  paste0("virustotal ", desc$Version)
}

#' Print package information and configuration status
#'
#' @return Invisible NULL
#' @export
#' @family utilities
virustotal_info <- function() {
  cat("VirusTotal R Package Information\n")
  cat("================================\n\n")
  
  # Version info
  cat("Version:", utils::packageDescription("virustotal")$Version, "\n")
  cat("R Version:", R.version.string, "\n\n")
  
  # API key status
  cat("API Key Status: ")
  if (is_api_key_configured()) {
    cat("\u2713 Configured\n")
  } else {
    cat("\u2717 Not configured (use set_key())\n")
  }
  
  # Rate limiting status
  rate_status <- get_rate_limit_status()
  cat("Rate Limit Status:\n")
  cat(sprintf("  Requests used: %d/%d\n", 
             rate_status$requests_used, rate_status$max_requests))
  cat(sprintf("  Requests remaining: %d\n", rate_status$requests_remaining))
  
  # Environment info
  cat("\nEnvironment: ")
  if (is_safe_environment()) {
    cat("\u2713 Safe\n")
  } else {
    cat("\u26A0 CI/Non-interactive\n")
  }
  
  cat("\nFor help, see: ?virustotal or https://docs.virustotal.com/reference\n")
  
  invisible(NULL)
}
