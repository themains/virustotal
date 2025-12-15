#' Add a vote to a URL
#'
#' @param url_id URL or URL ID from VirusTotal
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
#' post_url_votes(url_id='http://www.google.com', verdict='harmless')
#' }

post_url_votes <- function(url_id = NULL, verdict = NULL, ...) {

  assert_character(url_id, len = 1, any.missing = FALSE, min.chars = 1)

  if (is.null(verdict) || !verdict %in% c("harmless", "malicious")) {
    stop("Verdict must be either 'harmless' or 'malicious'.\n")
  }

  # If it looks like a URL, encode it to base64 (VirusTotal v3 requirement)
  if (grepl("^https?://", url_id)) {
    url_id <- base64encode(charToRaw(url_id))
    url_id <- gsub("=+$", "", url_id)  # Remove padding
  }

  res <- virustotal_POST(path = paste0("urls/", url_id, "/votes"),
                        body = list(data = list(type = "vote",
                                               attributes = list(verdict = verdict))), ...)

  res
}
