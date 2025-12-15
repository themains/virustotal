#' @title virustotal: Access Virustotal API
#' 
#' @description Access virustotal API. See \url{https://www.virustotal.com/}. 
#' Details about results of calls to the API can be found at \url{https://docs.virustotal.com/reference}.
#'
#' You will need credentials to use this application. 
#' If you haven't already, get the API Key at \url{https://www.virustotal.com/}.
#'
#'  
#' @importFrom httr GET content POST upload_file add_headers
#' @importFrom dplyr bind_rows
#' @importFrom utils read.table
#' @importFrom jsonlite fromJSON toJSON
#' @importFrom checkmate assert_character assert_file_exists
#' @importFrom rlang .data
#' @author Gaurav Sood
"_PACKAGE"

#' 
#' Base POST AND GET functions. Not exported.
#'
#' GET for the v2 API
#' 
#' @param query query list 
#' @param path  path to the specific API service url
#' @param key  A character string containing Virustotal API Key. The default is retrieved from \code{Sys.getenv("VirustotalToken")}.
#' @param \dots Additional arguments passed to \code{\link[httr]{GET}}.
#' @return list

virustotal2_GET <- function(query=list(), path = path,
                                     key = Sys.getenv("VirustotalToken"), ...) {

  if (identical(key, "")) {
        stop("Please set application key via set_key(key='key')).\n")
  }

  query$apikey <- key

  rate_limit()

  res <- GET("https://www.virustotal.com/", path = paste0("vtapi/v2/", path),
                                                             query = query, ...)
  virustotal_check(res)
  res <- content(res)

  res
}

#'
#' GET for the Current V3 API
#' 
#' @param path  path to the specific API service url
#' @param query query list 
#' @param key  A character string containing Virustotal API Key. The default is retrieved from \code{Sys.getenv("VirustotalToken")}.
#' @param \dots Additional arguments passed to \code{\link[httr]{GET}}.
#' @return list

virustotal_GET <- function(path, query = list(),
                          key = Sys.getenv("VirustotalToken"), ...) {

  if (identical(key, "")) {
        stop("Please set application key via set_key(key='key')).\n")
  }

  rate_limit()

  res <- GET("https://www.virustotal.com/", 
             path = paste0("api/v3/", path),
             query = query, 
             add_headers('x-apikey' = key), ...)

  virustotal_check(res)
  res <- content(res, as = "parsed", type = "application/json")

  res
}


#'
#' POST for the Current V3 API
#' 
#' @param path  path to the specific API service url
#' @param body request body (file upload or JSON data)
#' @param query query list 
#' @param key A character string containing Virustotal API Key. The default is retrieved from \code{Sys.getenv("VirustotalToken")}.
#' @param \dots Additional arguments passed to \code{\link[httr]{POST}}.
#' @return list

virustotal_POST <- function(path, body = NULL, query = list(),
                           key = Sys.getenv("VirustotalToken"), ...) {

  if (identical(key, "")) {
        stop("Please set application key via set_key(key='key')).\n")
  }

  rate_limit()

  res <- POST("https://www.virustotal.com/", 
              path = paste0("api/v3/", path),
              body = body,
              encode = "json",
              query = query,
              add_headers('x-apikey' = key), ...)

  virustotal_check(res)
  res <- content(res, as = "parsed", type = "application/json")

  res
}

#'
#' POST for V2 API
#' 
#' @param query query list 
#' @param body file 
#' @param path  path to the specific API service url
#' @param key A character string containing Virustotal API Key. The default is retrieved from \code{Sys.getenv("VirustotalToken")}.
#' @param \dots Additional arguments passed to \code{\link[httr]{POST}}.
#' @return list

virustotal2_POST <- function(query=list(), path = path, body=NULL,
                                     key = Sys.getenv("VirustotalToken"), ...) {

  if (identical(key, "")) {
        stop("Please set application key via set_key(key='key')).\n")
  }

  query$apikey <- key

  rate_limit()

  res <- POST("https://www.virustotal.com/", path = paste0("vtapi/v2/", path),
                                                query = query, body = body, ...)
  virustotal_check(res)
  res <- content(res)

  res
}

#' Request Response Verification
#' 
#' Enhanced error checking with structured error classes
#' 
#' @param req HTTP response object from httr
#' @return Invisible NULL on success, throws structured errors on failure
#' @family error handling
#' @keywords internal

virustotal_check <- function(req) {
  # Rate limit errors (check before general success cases)
  if (req$status_code == 204 || req$status_code == 429) {
    # Try to get retry-after header, with fallback to 60 if anything fails
    retry_after <- tryCatch({
      as.numeric(httr::headers(req)[["retry-after"]]) %||% 60
    }, error = function(e) {
      60  # Default fallback
    })
    
    stop(virustotal_rate_limit_error(
      message = "Rate limit exceeded. Only 4 requests per minute allowed.",
      retry_after = retry_after
    ))
  }
  
  # Success cases (after rate limit check)
  if (req$status_code < 400) return(invisible())
  
  # Authentication errors
  if (req$status_code == 401 || req$status_code == 403) {
    stop(virustotal_auth_error(
      message = "Authentication failed. Please check your API key."
    ))
  }
  
  # Not found errors
  if (req$status_code == 404) {
    stop(virustotal_error(
      message = "Resource not found.",
      status_code = req$status_code,
      response = req
    ))
  }
  
  # Server errors
  if (req$status_code >= 500) {
    stop(virustotal_error(
      message = paste("VirusTotal server error:", req$status_code),
      status_code = req$status_code,
      response = req
    ))
  }
  
  # Generic client errors
  stop(virustotal_error(
    message = paste("HTTP request failed with status", req$status_code),
    status_code = req$status_code,
    response = req
  ))
}

# Helper operator for default values
`%||%` <- function(x, y) if (is.null(x)) y else x

# The rate limiting function is now implemented in rate_limiting.R
# This legacy function is kept for backward compatibility but redirects to new implementation

#' Legacy rate limiting function
#' 
#' @keywords internal
rate_limit_legacy <- function() {
  .Deprecated("rate_limit", package = "virustotal", 
              msg = "Legacy rate limiting deprecated. Using modern implementation.")
  rate_limit()
}
