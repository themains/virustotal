#' @title virustotal: Access Virustotal API
#' 
#' @name virustotal-package
#' @aliases virustotal
#'
#' @description Access virustotal API. See \url{https://www.virustotal.com/}. 
#' Details about results of calls to the API can be found at \url{https://www.virustotal.com/en/documentation/public-api/}.
#'
#' Your need credentials to use this application. 
#' If you haven't already, you can get this at \url{https://www.virustotal.com/}.
#'
#'  
#' @importFrom httr GET content POST upload_file
#' @docType package
#' @author Gaurav Sood
NULL

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
