#' Add a comment to an IP address
#'
#'
#' @param ip IP address. String. Required.
#' @param comment Comment. String. Required.
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
#' post_ip_comments(ip = "64.233.160.0", comment = "test")
#' }

post_ip_comments <- function(ip = NULL, comment = NULL, ...) {

    assert_character(ip, len = 1, any.missing = FALSE, min.chars = 1)
    assert_character(comment, len = 1, any.missing = FALSE, min.chars = 1)

	comment_r = list("data" = list("type" = "comment", "attributes" = list("text" = comment)))

    res   <- virustotal_POST(path = paste0("ip_addresses/", ip, "/comments"),
                             body  = comment_r,...)

    res
}
