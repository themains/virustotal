#' @title virustotal: Access Virustotal API
#' 
#' @name virustotal-package
#' @aliases virustotal
#'
#' @description Access virustotal API. See \url{https://www.virustotal.com/}. 
#' Details about results of calls to the API can be found at \url{https://www.virustotal.com/en/documentation/public-api/}.
#'
#' You will need credentials to use this application. 
#' If you haven't already, get the API Key at \url{https://www.virustotal.com/}.
#'
#'  
#' @importFrom httr GET content POST upload_file
#' @importFrom plyr rbind.fill
#' @docType package
#' @author Gaurav Sood
NULL

#' 
#' Base POST AND GET functions. Not exported.
#'
#' GET
#' 
#' @param query query list 
#' @param path  path to the specific API service url
#' @param key  A character string containing Virustotal API Key. The default is retrieved from \code{Sys.getenv("VirustotalToken")}.
#' @param \dots Additional arguments passed to \code{\link[httr]{GET}}.
#' @return list

virustotal_GET <- 
function(query=list(), path = path, key = Sys.getenv("VirustotalToken"), ...) {

	if (identical(key, "")) {
        stop("Please set application id and password using set_key(key='key')).")
	}

	query$apikey <- key

	res <- GET("http://www.virustotal.com/", path = paste0("vtapi/v2/", path), query = query, ...)
	virustotal_check(res)
	res <- content(res)

	res
}

#'
#' POST
#' 
#' @param query query list 
#' @param body file 
#' @param path  path to the specific API service url
#' @param key A character string containing Virustotal API Key. The default is retrieved from \code{Sys.getenv("VirustotalToken")}.
#' @param \dots Additional arguments passed to \code{\link[httr]{POST}}.
#' @return list

virustotal_POST <- 
function(query=list(), path = path, body=NULL, key = Sys.getenv("VirustotalToken"), ...) {

	if (identical(key, "")) {
        stop("Please set application id and password using set_key(key='key')).")
	}

	query$apikey <- key

	res <- POST("http://www.virustotal.com/", path = paste0("vtapi/v2/", path), query = query, body = body, ...)
	virustotal_check(res)
	res <- content(res)

	res
}

#'
#' Request Response Verification
#' 
#' @param  req request
#' @return in case of failure, a message

virustotal_check <- 
function(req) {
  if (req$status_code < 400) return(invisible())

  stop("HTTP failure: ", req$status_code, "\n", call. = FALSE)
} 
