#' Add a comment to an Internet domain
#'
#' @param domain domain name. Required.
#' @param comment comment text. Required. Words starting with # become tags.
#' @param \dots Additional arguments passed to \code{\link{virustotal_POST}}.
#'
#' @return named list
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
#' post_domain_comments(domain = "https://google.com", comment = "Great!")
#' }
post_domain_comments <- function(domain = NULL, comment = NULL, ...) {
  assert_character(domain, len = 1, any.missing = FALSE, min.chars = 1)
  assert_character(comment, len = 1, any.missing = FALSE, min.chars = 1)

  domain <- gsub("^http://|^https://", "", domain)

  comment_body <- list(
    data = list(
      type = "comment",
      attributes = list(text = comment)
    )
  )

  res <- virustotal_POST(
    path = paste0("domains/", domain, "/comments"),
    body = comment_body, ...
  )

  res
}
