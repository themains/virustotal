#' Add comments on Files and URLs
#'
#' Add comments on files and URLs. For instance, flagging false positives, adding details about malware, instructions for cleaning malware, etc.
#' 
#' @param hash hash for the resource you want to comment on; Required; String
#' @param comment review; Required; String
#' @param \dots Additional arguments passed to \code{\link{virustotal2_GET}}.
#'  
#' @return data.frame with 2 columns: \code{response_code}, \code{verbose_msg} 
#' \itemize{
#' \item If the hash is incorrect or a duplicate comment is posted, \code{response_code} will be \code{0} 
#' \item If the hash is incorrect, \code{verbose_msg} will be \code{'Invalid resource'} 
#' \item If a duplicate comment is posted, \code{verbose_msg} will be \code{'Duplicate comment'} 
#' \item If a comment is posted successfully, \code{response_code} will be \code{1} 
#' and \code{verbose_msg} will be \code{'Your comment was successfully posted'} 
#' }
#' 
#' @seealso \code{\link{set_key}} for setting the API key
#'   
#' @export
#' 
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' 
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#'   
#' add_comments(hash='99017f6eebbac24f351415dd410d522d', comment="This is great.")
#' 
#' 
#' }

add_comments <- function(hash = NULL, comment = NULL, ...) {

  if (!is.character(hash)) {
        stop("Must specify the hash.\n")
    }

  if (!is.character(comment)) {
        stop("Must provide an actual comment.\n")
    }

    params <- list(resource = hash, comment = comment)

    .Deprecated("")

    res   <- virustotal2_POST(path = "comments/put", query = params, ...)

    as.data.frame(res)
}
