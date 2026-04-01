#' Retrieve relationships for a file
#'
#' @param hash File hash (MD5, SHA1, or SHA256)
#' @param relationship Type of relationship: "behaviours", "bundled_files", "compression_parents", "contacted_domains", "contacted_ips", "contacted_urls", "dropped_files", "execution_parents", "itw_domains", "itw_ips", "itw_urls", "overlay_parents", "pcap_parents", "pe_resource_parents", "similar_files", "submissions"
#' @param limit Number of relationships to retrieve. Integer. Optional. Default is 10.
#' @param cursor String for pagination. Optional.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return list containing file relationships
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
#' get_file_relationships(hash='99017f6eebbac24f351415dd410d522d', 
#'                        relationship='contacted_domains')
#' }

get_file_relationships <- function(hash = NULL, relationship = NULL, 
                                  limit = NULL, cursor = NULL, ...) {

  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)
  assert_character(relationship, len = 1, any.missing = FALSE, min.chars = 1)

  valid_relationships <- c("behaviours", "bundled_files", "compression_parents", 
                          "contacted_domains", "contacted_ips", "contacted_urls", 
                          "dropped_files", "execution_parents", "itw_domains", 
                          "itw_ips", "itw_urls", "overlay_parents", "pcap_parents", 
                          "pe_resource_parents", "similar_files", "submissions")

  if (!relationship %in% valid_relationships) {
    stop("Invalid relationship type")
  }

  res <- virustotal_GET(path = paste0("files/", hash, "/relationships/", relationship),
                       query = list(limit = limit, cursor = cursor), ...)

  res
}
