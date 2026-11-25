#' Add a vote for a hostname or domain
#'
#' @inheritParams domain_report
#' @param vote Either `harmless` or `malicious`.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#'
#' @return named list
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
#' post_domain_votes("http://google.com", vote = "malicious")
#' }
post_domain_votes <- function(domain = NULL, vote = NULL, ...) {
  domain <- sanitize_domain(domain)
  assert_character(vote, len = 1, any.missing = FALSE, min.chars = 1)

  validate_verdict(vote, "vote")

  vote_body <- list(
    data = list(
      type = "vote",
      attributes = list(verdict = vote)
    )
  )

  res <- virustotal_POST(
    path = paste0("domains/", domain, "/votes"),
    body = vote_body, ...
  )

  res
}
