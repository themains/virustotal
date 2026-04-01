#' Get File Behaviour MITRE ATT&CK Trees
#'
#' Retrieves MITRE ATT&CK techniques observed in file behaviour reports.
#'
#' @param hash File hash (MD5, SHA1, or SHA256). Required.
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#'
#' @return list containing MITRE ATT&CK technique mappings
#'
#' @export
#'
#' @references \url{https://docs.virustotal.com/reference}
#'
#' @seealso \code{\link{set_key}} for setting the API key,
#'   \code{\link{get_file_behaviour_summary}} for behaviour summary
#'
#' @examples \dontrun{
#'
#' # Before calling the function, set the API key using set_key('api_key_here')
#'
#' get_file_behaviour_mitre_trees(hash='99017f6eebbac24f351415dd410d522d')
#' }

get_file_behaviour_mitre_trees <- function(hash = NULL, ...) {

  assert_character(hash, len = 1, any.missing = FALSE, min.chars = 1)

  res <- virustotal_GET(
    path = paste0("files/", hash, "/behaviour_mitre_trees"),
    ...
  )

  res
}
