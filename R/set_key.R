#' Set API Key
#'
#' Before anything else, get the API key from \url{https://www.virustotal.com/en/}.
#' Next, use \code{\link{set_key}} to store the API key in an environment variable \code{VirustotalToken}. 
#' Once you have set the API key, you can use any of the functions.
#'  
#' @param api_key API key. String. Required. 
#' 
#' @export
#' 
#' @references \url{https://docs.virustotal.com/reference}
#' 
#' @examples \dontrun{
#' 
#' set_key('api_key_here')
#' 
#' }

set_key <- function(api_key = NULL) {

  if (!is.character(api_key)) stop("Must specify API Key.\n")

  Sys.setenv(VirustotalToken = api_key)

}
