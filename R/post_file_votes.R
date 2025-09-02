#' Add a vote to a file
#'
#' @param hash File hash (MD5, SHA1, or SHA256)
#' @param verdict Vote verdict: "harmless" or "malicious"
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return list containing response data
#'  
#' @export
#' 
#' @references \url{https://docs.virustotal.com/reference}
#' 
#' @seealso \code{\link{set_key}} for setting the API key
#'
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' post_file_votes(hash='99017f6eebbac24f351415dd410d522d', verdict='malicious')
#' }

post_file_votes <- function(hash = NULL, verdict = NULL, ...) {

  if (is.null(hash) || !is.character(hash) || nchar(hash) == 0) {
    stop("Must specify a valid file hash (MD5, SHA1, or SHA256).\n")
  }

  if (is.null(verdict) || !verdict %in% c("harmless", "malicious")) {
    stop("Verdict must be either 'harmless' or 'malicious'.\n")
  }

  res <- virustotal_POST(path = paste0("files/", hash, "/votes"),
                        body = list(data = list(type = "vote", 
                                               attributes = list(verdict = verdict))), ...)

  res
}
