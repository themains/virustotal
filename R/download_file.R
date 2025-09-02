#' Download a file from VirusTotal
#'
#' @param hash File hash (MD5, SHA1, or SHA256)
#' @param output_path Local path to save the downloaded file. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return Raw file content or saves file to specified path
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
#' download_file(hash='99017f6eebbac24f351415dd410d522d', 
#'               output_path='/tmp/downloaded_file')
#' }

download_file <- function(hash = NULL, output_path = NULL, ...) {

  if (is.null(hash) || !is.character(hash) || nchar(hash) == 0) {
    stop("Must specify a valid file hash (MD5, SHA1, or SHA256).\n")
  }

  # Note: This endpoint returns raw file content, not JSON
  res <- GET("https://www.virustotal.com/",
             path = paste0("api/v3/files/", hash, "/download"),
             add_headers("x-apikey" = Sys.getenv("VirustotalToken")), ...)

  virustotal_check(res)

  if (!is.null(output_path)) {
    writeBin(content(res, "raw"), output_path)
    return(paste("File downloaded to:", output_path))
  } else {
    return(content(res, "raw"))
  }
}
