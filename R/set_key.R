#' Set API Key
#'
#' 
#' @param api_key String (API Key)
#' 
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' set_key('api_key_here')
#' }

set_key <- function(api_key=NULL) {
	
	if (is.null(api_key)) stop("Get API Key")

    Sys.setenv(VirustotalToken = api_key)

}


