#' S3 Classes for VirusTotal Responses
#'
#' @description
#' S3 classes to provide structured responses and better user experience
#' when working with VirusTotal API results.
#' 
#' @name virustotal-classes
#' @keywords internal
#' @family response classes
NULL

#' Create a VirusTotal file scan result
#'
#' @param data Raw API response data
#' @return Object of class \code{virustotal_file_scan}
#' @keywords internal
#' @export
#' @family response classes
virustotal_file_scan <- function(data) {
  structure(
    data,
    class = c("virustotal_file_scan", "virustotal_response", "list")
  )
}

#' Create a VirusTotal file report
#'
#' @param data Raw API response data
#' @return Object of class \code{virustotal_file_report}
#' @keywords internal
#' @export
#' @family response classes
virustotal_file_report <- function(data) {
  structure(
    data,
    class = c("virustotal_file_report", "virustotal_response", "list")
  )
}

#' Create a VirusTotal URL scan result
#'
#' @param data Raw API response data
#' @return Object of class \code{virustotal_url_scan}
#' @keywords internal
#' @export
#' @family response classes
virustotal_url_scan <- function(data) {
  structure(
    data,
    class = c("virustotal_url_scan", "virustotal_response", "list")
  )
}

#' Create a VirusTotal domain report
#'
#' @param data Raw API response data
#' @return Object of class \code{virustotal_domain_report}
#' @keywords internal
#' @export
#' @family response classes
virustotal_domain_report <- function(data) {
  structure(
    data,
    class = c("virustotal_domain_report", "virustotal_response", "list")
  )
}

#' Create a VirusTotal IP report
#'
#' @param data Raw API response data
#' @return Object of class \code{virustotal_ip_report}
#' @keywords internal
#' @export
#' @family response classes
virustotal_ip_report <- function(data) {
  structure(
    data,
    class = c("virustotal_ip_report", "virustotal_response", "list")
  )
}

#' Print method for VirusTotal responses
#' 
#' @param x A virustotal_response object
#' @param ... Additional arguments (unused)
#' @keywords internal
print.virustotal_response <- function(x, ...) {
  cat("VirusTotal API Response\n")
  cat("======================\n\n")
  
  # Get the specific class
  specific_class <- class(x)[1]
  type <- gsub("virustotal_", "", specific_class)
  type <- gsub("_", " ", type)
  type <- tools::toTitleCase(type)
  
  cat("Type:", type, "\n")
  
  if (!is.null(x$data$id)) {
    cat("ID:", x$data$id, "\n")
  }
  
  if (!is.null(x$data$type)) {
    cat("Resource Type:", x$data$type, "\n")
  }
  
  cat("\n")
  invisible(x)
}

#' Print method for file reports
#' 
#' @param x A virustotal_file_report object
#' @param ... Additional arguments (unused)
#' @keywords internal
print.virustotal_file_report <- function(x, ...) {
  NextMethod()
  
  if (!is.null(x$data$attributes)) {
    attrs <- x$data$attributes
    
    # Detection summary
    if (!is.null(attrs$last_analysis_stats)) {
      stats <- attrs$last_analysis_stats
      cat("Detection Summary:\n")
      cat(sprintf("  Malicious: %d\n", stats$malicious %||% 0))
      cat(sprintf("  Suspicious: %d\n", stats$suspicious %||% 0))
      cat(sprintf("  Undetected: %d\n", stats$undetected %||% 0))
      cat(sprintf("  Harmless: %d\n", stats$harmless %||% 0))
      cat("\n")
    }
    
    # File info
    if (!is.null(attrs$size)) {
      cat(sprintf("File Size: %s bytes\n", format(attrs$size, big.mark = ",")))
    }
    
    if (!is.null(attrs$sha256)) {
      cat(sprintf("SHA256: %s\n", attrs$sha256))
    }
    
    cat("\n")
  }
  
  invisible(x)
}

#' Print method for domain reports
#' 
#' @param x A virustotal_domain_report object
#' @param ... Additional arguments (unused)
#' @keywords internal
print.virustotal_domain_report <- function(x, ...) {
  NextMethod()
  
  if (!is.null(x$data$attributes)) {
    attrs <- x$data$attributes
    
    # Domain reputation
    if (!is.null(attrs$last_analysis_stats)) {
      stats <- attrs$last_analysis_stats
      cat("Domain Reputation:\n")
      cat(sprintf("  Malicious: %d\n", stats$malicious %||% 0))
      cat(sprintf("  Suspicious: %d\n", stats$suspicious %||% 0))
      cat(sprintf("  Undetected: %d\n", stats$undetected %||% 0))
      cat(sprintf("  Harmless: %d\n", stats$harmless %||% 0))
      cat("\n")
    }
    
    # Categories
    if (!is.null(attrs$categories)) {
      cats <- names(attrs$categories)
      if (length(cats) > 0) {
        cat("Categories:", paste(cats, collapse = ", "), "\n")
      }
    }
    
    cat("\n")
  }
  
  invisible(x)
}

#' Summary method for VirusTotal responses
#' 
#' @param object A virustotal_response object
#' @param ... Additional arguments (unused)
#' @keywords internal
summary.virustotal_response <- function(object, ...) {
  print(object)
  
  if (inherits(object, "virustotal_file_report") && !is.null(object$data$attributes$last_analysis_results)) {
    results <- object$data$attributes$last_analysis_results
    
    # Show top detections
    detections <- sapply(results, function(x) x$category %||% "undetected")
    malicious <- names(detections[detections == "malicious"])
    
    if (length(malicious) > 0) {
      cat("Engines detecting as malicious:\n")
      cat(paste("  -", malicious[1:min(10, length(malicious))]), sep = "\n")
      if (length(malicious) > 10) {
        cat(sprintf("  ... and %d more\n", length(malicious) - 10))
      }
      cat("\n")
    }
  }
  
  invisible(object)
}

