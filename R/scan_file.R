#' Submit a file for scanning
#'
#' @param file_path Required; Path to the document
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#' 
#' @return data.frame with the following columns: 
#' \code{type, id, links}
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
#' scan_file(file_path='path_to_suspicious_file')
#' }

scan_file <- function(file_path = NULL, ...) {

  if (is.null(file_path) || !is.character(file_path)) {
    stop("file_path must be a character string pointing to a valid file.\n")
  }
  
  if (!file.exists(file_path)) {
    stop("The file doesn't exist. Please check the path.\n")
  }

  res <- virustotal_POST(path = "files", 
                        body = list(file = upload_file(file_path)),
                        ...)

  as.data.frame(res)
}
