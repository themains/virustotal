#' Retrieve relationships for a URL
#'
#' @param url_id URL or URL ID from VirusTotal
#' @param relationship Type of relationship: "communicating_files", "downloaded_files", "graphs", "last_serving_ip_address", "network_location", "redirecting_urls", "redirects_to", "referrer_urls", "submissions"
#' @param limit Number of relationships to retrieve. Integer. Optional. Default is 10.
#' @param cursor String for pagination. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return list containing URL relationships
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
#' get_url_relationships(url_id='http://www.google.com',
#'                       relationship='communicating_files')
#' }

get_url_relationships <- function(url_id = NULL, relationship = NULL,
                                 limit = NULL, cursor = NULL, ...) {

  assert_character(url_id, len = 1, any.missing = FALSE, min.chars = 1)
  assert_character(relationship, len = 1, any.missing = FALSE, min.chars = 1)

  valid_relationships <- c("communicating_files", "downloaded_files", "graphs",
                          "last_serving_ip_address", "network_location",
                          "redirecting_urls", "redirects_to", "referrer_urls",
                          "submissions")

  if (!relationship %in% valid_relationships) {
    stop("Invalid relationship type. Must be one of: ",
         paste(valid_relationships, collapse = ", "), "\n")
  }

  # If it looks like a URL, encode it to base64 (VirusTotal v3 requirement)
  if (grepl("^https?://", url_id)) {
    url_id <- base64encode(charToRaw(url_id))
    url_id <- gsub("=+$", "", url_id)  # Remove padding
  }

  res <- virustotal_GET(path = paste0("urls/", url_id, "/relationships/", relationship),
                       query = list(limit = limit, cursor = cursor), ...)

  res
}
