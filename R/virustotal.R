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
#' @importFrom plyr rbind.fill ldply
#' @importFrom utils read.table
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

#'
#' Request Response Verification
#' 
#' @param  req request
#' @return in case of failure, a message

virustotal_check <- function(req) {

  if (req$status_code == 204) stop("Rate Limit Exceeded.
                                          Only 4 Queries per minute allowed.\n")
  if (req$status_code < 400) return(invisible())

  stop("HTTP failure: ", req$status_code, "\n", call. = FALSE)
}

#' 
#' Rate Limits
#' 
#' Virustotal requests throttled at 4 per min. The function creates an env. var.
#' that tracks number of requests per minute, and enforces appropriate waiting.
#' 

rate_limit <- function() {

  # First request --- initialize time of first request and request count
  if (Sys.getenv("VT_RATE_LIMIT") == "") {
    return(Sys.setenv(VT_RATE_LIMIT = paste0(0, ",", Sys.time(), ",", 0)))
  }

  rate_lim         <- Sys.getenv("VT_RATE_LIMIT")
  req_count        <- as.numeric(gsub(",.*", "", rate_lim)) + 1
  past_duration    <- as.numeric(strsplit(rate_lim, ",")[[1]][3],
                                                                 units = "secs")
  current_duration <- difftime(Sys.time(),
                    as.POSIXct(strsplit(rate_lim, ",")[[1]][2]), units = "secs")

  if (current_duration > 60) {
    return(Sys.setenv(VT_RATE_LIMIT = paste0(1, ",", Sys.time(), ",", 0)))
  }

  net_duration     <- past_duration + current_duration

  if (req_count > 4 & net_duration <= 60) {

    Sys.sleep(60 -  net_duration)
    return(Sys.setenv(VT_RATE_LIMIT = paste0(1, ",", Sys.time(), ",", 0)))
  }

  return(Sys.setenv(VT_RATE_LIMIT =
                         paste0(req_count, ",", Sys.time(), ",", net_duration)))
}
