#' Add comments on Files and URLs
#'
#' Add comments on files and URLs. For instance, flagging false positives, adding details about malware, instructions for cleaning malware, etc.
#' 
#' @param hash hash for the resource you want to comment on; Required; String
#' @param comment review; Required; String
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'  
#' @return data.frame with 2 columns: response_code, verbose_msg
#'   
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' add_comments(hash='99017f6eebbac24f351415dd410d522d', comment="This is great.")
#' }

add_comments <- function(hash = NULL, comment = NULL, ...) {

	if (!is.character(hash)) {
        stop("Must specify the hash.")
    }

	if (!is.character(comment)) {
        stop("Must provide an actual comment.")
    }

    params <- list(resource = hash, comment= comment)
    
    res   <- virustotal_POST(path="comments/put", query = params, ...)
    
    as.data.frame(do.call(cbind, res))
}

