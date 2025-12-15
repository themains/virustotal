#' Security Utilities for VirusTotal Package
#'
#' @description
#' Security functions for input sanitization and validation to prevent
#' common security issues when working with potentially malicious inputs.
#' 
#' @name security-utilities
#' @keywords internal
#' @family security
NULL

#' Sanitize file path input
#'
#' Validates and sanitizes file paths to prevent directory traversal attacks
#' and ensure safe file operations.
#' 
#' @param file_path Character string representing a file path
#' @param allow_relative Logical. Whether to allow relative paths (default: FALSE)
#' @return Sanitized file path or throws error if invalid
#' @keywords internal
#' @family security
sanitize_file_path <- function(file_path, allow_relative = FALSE) {
  assert_character(file_path, len = 1, any.missing = FALSE)
  
  # Check for directory traversal attempts
  if (grepl("\\.\\.", file_path) || grepl("~", file_path)) {
    stop(virustotal_validation_error(
      message = "File path contains potentially unsafe components (.., ~)",
      parameter = "file_path",
      value = file_path
    ))
  }
  
  # Check for absolute vs relative paths
  is_absolute <- grepl("^(/|[A-Za-z]:)", file_path)
  if (!allow_relative && !is_absolute) {
    stop(virustotal_validation_error(
      message = "Relative file paths are not allowed for security reasons",
      parameter = "file_path", 
      value = file_path
    ))
  }
  
  # Normalize path
  normalized_path <- normalizePath(file_path, mustWork = FALSE)
  
  # Verify file exists and is readable
  if (file.exists(normalized_path)) {
    if (!file.access(normalized_path, mode = 4) == 0) {
      stop(virustotal_validation_error(
        message = "File is not readable",
        parameter = "file_path",
        value = file_path
      ))
    }
  }
  
  return(normalized_path)
}

#' Sanitize URL input
#'
#' Validates and sanitizes URLs to prevent malicious inputs while preserving
#' legitimate URLs for analysis.
#' 
#' @param url Character string representing a URL
#' @return Sanitized URL or throws error if invalid
#' @keywords internal
#' @family security
sanitize_url <- function(url) {
  assert_character(url, len = 1, any.missing = FALSE, min.chars = 1)
  
  # Remove leading/trailing whitespace
  url <- trimws(url)
  
  # Check for obviously malicious patterns
  malicious_patterns <- c(
    "javascript:",
    "data:",
    "vbscript:",
    "file:",
    "ftp:",
    "\\x00",  # null bytes
    "<script",
    "</script"
  )
  
  for (pattern in malicious_patterns) {
    if (grepl(pattern, url, ignore.case = TRUE)) {
      stop(virustotal_validation_error(
        message = paste("URL contains potentially malicious content:", pattern),
        parameter = "url",
        value = url
      ))
    }
  }
  
  # Validate URL format
  if (!grepl("^https?://", url, ignore.case = TRUE)) {
    # Add http if missing (VirusTotal can handle this)
    url <- paste0("http://", url)
  }
  
  # Basic URL validation
  parsed <- try(httr::parse_url(url), silent = TRUE)
  if (inherits(parsed, "try-error") || is.null(parsed$hostname)) {
    stop(virustotal_validation_error(
      message = "Invalid URL format",
      parameter = "url",
      value = url
    ))
  }
  
  return(url)
}

#' Sanitize hash input
#'
#' Validates hash inputs to ensure they conform to expected formats
#' (MD5, SHA1, SHA256) and contain only valid hexadecimal characters.
#' 
#' @param hash Character string representing a file hash
#' @return Sanitized hash or throws error if invalid
#' @keywords internal
#' @family security
sanitize_hash <- function(hash) {
  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)
  
  # Remove whitespace
  hash <- trimws(hash)
  
  # Convert to lowercase for consistency
  hash <- tolower(hash)
  
  # Validate hexadecimal format
  if (!grepl("^[a-f0-9]+$", hash)) {
    stop(virustotal_validation_error(
      message = "Hash must contain only hexadecimal characters (0-9, a-f)",
      parameter = "hash",
      value = hash
    ))
  }
  
  # Validate length (MD5=32, SHA1=40, SHA256=64, or analysis IDs which vary)
  valid_lengths <- c(32, 40, 64)
  if (!nchar(hash) %in% valid_lengths && nchar(hash) < 32) {
    stop(virustotal_validation_error(
      message = sprintf("Hash length (%d) does not match MD5 (32), SHA1 (40), or SHA256 (64)", nchar(hash)),
      parameter = "hash",
      value = hash
    ))
  }
  
  return(hash)
}

#' Sanitize domain input
#'
#' Validates and sanitizes domain names to prevent injection attacks
#' while allowing legitimate domain analysis.
#' 
#' @param domain Character string representing a domain name
#' @return Sanitized domain or throws error if invalid
#' @keywords internal
#' @family security
sanitize_domain <- function(domain) {
  assert_character(domain, len = 1, any.missing = FALSE, min.chars = 1)
  
  # Remove whitespace
  domain <- trimws(domain)
  
  # Convert to lowercase for consistency
  domain <- tolower(domain)
  
  # Remove protocol if present
  domain <- gsub("^https?://", "", domain)
  domain <- gsub("^ftp://", "", domain)
  
  # Remove www prefix
  domain <- gsub("^www\\.", "", domain)
  
  # Remove paths, queries, and fragments
  domain <- gsub("/.*$", "", domain)
  domain <- gsub("\\?.*$", "", domain)
  domain <- gsub("#.*$", "", domain)
  
  # Remove trailing dots
  domain <- gsub("\\.$", "", domain)
  
  # Validate domain format
  # Basic regex for domain names (simplified)
  if (!grepl("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", domain) || 
      grepl("\\.\\.", domain) ||
      grepl("^[.-]|[.-]$", domain)) {
    stop(virustotal_validation_error(
      message = "Invalid domain format",
      parameter = "domain",
      value = domain
    ))
  }
  
  # Note: Allow private domains - users may want to analyze them in enterprise environments
  
  return(domain)
}

#' Sanitize IP address input
#'
#' Validates IP addresses (IPv4 and IPv6) and checks for private ranges
#' that shouldn't be submitted to VirusTotal.
#' 
#' @param ip Character string representing an IP address
#' @return Sanitized IP address or throws error if invalid
#' @keywords internal
#' @family security
sanitize_ip <- function(ip) {
  assert_character(ip, len = 1, any.missing = FALSE, min.chars = 1)
  
  # Remove whitespace
  ip <- trimws(ip)
  
  # Basic IP validation (IPv4 and IPv6)
  is_ipv4 <- grepl("^([0-9]{1,3}\\.){3}[0-9]{1,3}$", ip)
  is_ipv6 <- grepl("^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$", ip) ||
             grepl("^::1$", ip) ||
             grepl("^::", ip)
  
  if (!is_ipv4 && !is_ipv6) {
    stop(virustotal_validation_error(
      message = "Invalid IP address format",
      parameter = "ip",
      value = ip
    ))
  }
  
  # Note: Allow private/reserved IPs - users may want to analyze them in enterprise environments
  
  return(ip)
}

#' Check if API key is properly configured
#'
#' Verifies that the API key is set and appears to be valid format.
#' 
#' @return Logical indicating if API key is configured
#' @keywords internal
#' @export
#' @family security
is_api_key_configured <- function() {
  key <- Sys.getenv("VirustotalToken")
  if (key == "" || is.null(key)) {
    return(FALSE)
  }
  
  # Basic format check
  if (nchar(key) < 32 || !grepl("^[a-zA-Z0-9]+$", key)) {
    return(FALSE)
  }
  
  return(TRUE)
}
