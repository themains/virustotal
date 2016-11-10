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
#' @importFrom plyr rbind.fill ldply
#' @importFrom utils read.table
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

	rate_limit()

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

	rate_limit()

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

  if (req$status_code == 204) stop("Rate Limit Exceeded. Only 4 Queries per minute allowed.")
  if (req$status_code < 400) return(invisible())

  stop("HTTP failure: ", req$status_code, "\n", call. = FALSE)
} 

#' 
#' Rate Limits
#' 
#' Virustotal requests throttled at 4 per minute. This function creates an env. variable 
#' that tracks number of requests per minute, and enforces appropriate waiting.
#' 

rate_limit <- function() {

	# First request --- initialize time of first request and request count
	if (Sys.getenv("VT_RATE_LIMIT") == "") return(Sys.setenv(VT_RATE_LIMIT = paste0(0, ",", Sys.time(), ",", 0)))

	rate_lim         <- Sys.getenv("VT_RATE_LIMIT") 
	req_count        <- as.numeric(gsub(",.*", "", rate_lim)) + 1
	past_duration    <- as.numeric(strsplit(rate_lim, ",")[[1]][3], units="secs")	
	current_duration <- difftime(Sys.time(), as.POSIXct(strsplit(rate_lim, ",")[[1]][2]), units = "secs") 

	if (current_duration > 60) return(Sys.setenv(VT_RATE_LIMIT = paste0(1, ",", Sys.time(), ",", 0)))

	net_duration     <- past_duration + current_duration

	if (req_count > 4 & net_duration <= 60) { 
		Sys.sleep(60 -  net_duration)
		return(Sys.setenv(VT_RATE_LIMIT = paste0(1, ",", Sys.time(), ",", 0)))
	}

	return(Sys.setenv(VT_RATE_LIMIT = paste0(req_count, ",", Sys.time(), ",", net_duration)))
}
