#' Set API Key
#'
#' 
#' @param api_key String (API Key)
#' 
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' set_token('api_key_here')
#' }

set_key <- function(api_key=NULL) {
	
	if (is.null(api_key)) "Get API Key"

    Sys.setenv(VirustotalToken = api_key)

}


