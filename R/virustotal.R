#' @title virustotal: Access Virustotal API
#'
#' @description Access virustotal API. See \url{https://www.virustotal.com/}.
#'   Details about API calls: \url{https://docs.virustotal.com/reference}.
#'
#' You will need credentials to use this application.
#' If you haven't already, get the API Key at \url{https://www.virustotal.com/}.
#'
#' @section Options:
#' \describe{
#'   \item{\code{virustotal.timeout}}{Request timeout in seconds. Default 60.}
#'   \item{\code{virustotal.max_tries}}{Maximum attempts per request; retries
#'     honor HTTP 429/503 and their \code{Retry-After} header. Default 3.}
#'   \item{\code{virustotal.requests_per_minute}}{Client-side throttle.
#'     Default 4, the public API allowance; premium keys can raise it.}
#'   \item{\code{virustotal.throttle}}{Set \code{FALSE} to disable the
#'     client-side throttle entirely. Default \code{TRUE}.}
#' }
#'
#' @importFrom httr2 request req_url_path_append req_headers_redacted req_user_agent req_timeout
#' @importFrom httr2 req_error req_retry req_throttle req_url_query req_method
#' @importFrom httr2 req_body_json req_body_form req_body_multipart req_perform
#' @importFrom httr2 resp_status resp_header resp_body_string resp_body_raw url_parse
#' @importFrom jsonlite fromJSON
#' @importFrom curl form_file
#' @importFrom openssl base64_encode
#' @importFrom checkmate assert_character assert_file_exists assert_numeric
#' @importFrom rlang %||%
#' @importFrom tools toTitleCase
#' @importFrom utils packageVersion
#' @author Gaurav Sood
"_PACKAGE"

vt_base_url <- "https://www.virustotal.com/api/v3"

#' Build the shared request object
#'
#' Every endpoint funnels through here, so the user agent, timeout, retry
#' policy and client-side throttle apply uniformly -- including the binary
#' download endpoints that used to bypass them.
#'
#' @param path Path below \code{/api/v3}, already assembled.
#' @param key A character string containing the VirusTotal API key.
#' @return An \code{httr2} request.
#' @keywords internal
vt_request <- function(path, key = vt_key()) {
  req <- request(vt_base_url)
  req <- req_url_path_append(req, path)
  req <- req_headers_redacted(req, `x-apikey` = key)
  req <- req_user_agent(req, paste0(
    "virustotal-r/", packageVersion("virustotal"),
    " (https://github.com/themains/virustotal)"
  ))
  req <- req_timeout(req, getOption("virustotal.timeout", 60))
  # Status handling stays ours: virustotal_check() turns failures into the
  # package's condition classes, so httr2's own conversion is switched off.
  # req_retry() still honors 429/503 and Retry-After before we ever see the
  # response; its transience logic is independent of is_error.
  req <- req_error(req, is_error = function(resp) FALSE)
  req <- req_retry(
    req,
    max_tries = getOption("virustotal.max_tries", 3),
    retry_on_failure = FALSE
  )
  if (isTRUE(getOption("virustotal.throttle", TRUE))) {
    req <- req_throttle(
      req,
      capacity = getOption("virustotal.requests_per_minute", 4),
      fill_time_s = 60,
      realm = "virustotal"
    )
  }
  req
}

vt_perform <- function(req) {
  resp <- req_perform(req)
  virustotal_check(resp)
  record_request()
  resp
}

#'
#' GET for the Current V3 API
#'
#' @param path  path to the specific API service url
#' @param query query list
#' @param key A character string containing the VirusTotal API key.
#'   Default: \code{vt_key()}, which reads \code{VIRUSTOTAL_API_KEY} and then
#'   the historical \code{VirustotalToken}.
#' @param \dots Ignored. Earlier versions forwarded these to
#'   \code{httr::GET}; configure requests with the package options instead
#'   (see \code{\link{virustotal}}).
#' @return list
#' @keywords internal

# The HTTP-verb casing is deliberate and predates the lint standard; renaming
# would churn every endpoint file and the test mocks for zero behavior.
virustotal_GET <- function(path, query = list(), # nolint: object_name_linter.
                           key = vt_key(), ...) {
  req <- vt_request(path, key)
  if (length(query)) req <- req_url_query(req, !!!query)
  resp <- vt_perform(req)
  fromJSON(resp_body_string(resp), simplifyVector = FALSE)
}


#'
#' POST for the Current V3 API
#'
#' @param path  path to the specific API service url
#' @param body request body (file upload or JSON data)
#' @param query query list
#' @param key A character string containing the VirusTotal API key.
#'   Default: \code{vt_key()}, which reads \code{VIRUSTOTAL_API_KEY} and then
#'   the historical \code{VirustotalToken}.
#' @param encode Body encoding. One of \code{"json"} (the default),
#'   \code{"form"} or \code{"multipart"}.
#' @param \dots Ignored. Earlier versions forwarded these to
#'   \code{httr::POST}; configure requests with the package options instead
#'   (see \code{\link{virustotal}}).
#' @return list
#' @keywords internal

virustotal_POST <- function(path, body = NULL, query = list(), # nolint: object_name_linter.
                            key = vt_key(),
                            encode = "json", ...) {
  req <- vt_request(path, key)
  if (length(query)) req <- req_url_query(req, !!!query)
  req <- if (is.null(body)) {
    req_method(req, "POST")
  } else {
    switch(encode,
      json = req_body_json(req, body),
      form = req_body_form(req, !!!body),
      multipart = req_body_multipart(req, !!!body),
      stop(virustotal_validation_error(
        message = "encode must be one of 'json', 'form', 'multipart'",
        parameter = "encode",
        value = encode
      ))
    )
  }
  resp <- vt_perform(req)
  fromJSON(resp_body_string(resp), simplifyVector = FALSE)
}

#' GET a binary body from the V3 API
#'
#' For the download and sandbox-artifact endpoints, which return file
#' content rather than JSON. Performed in memory so an error body is never
#' written to a caller's output path.
#'
#' @param path Path below \code{/api/v3}.
#' @param key A character string containing the VirusTotal API key.
#' @return A raw vector.
#' @keywords internal
virustotal_GET_raw <- function(path, key = vt_key()) { # nolint: object_name_linter.
  resp <- vt_perform(vt_request(path, key))
  resp_body_raw(resp)
}

#' Request Response Verification
#'
#' Enhanced error checking with structured error classes
#'
#' @param resp An \code{httr2} response object
#' @return Invisible NULL on success, throws structured errors on failure
#' @family error handling
#' @keywords internal

virustotal_check <- function(resp) {
  status <- resp_status(resp)

  # 204 was the v2 API's out-of-quota signal; v3 uses 429. No v3 endpoint
  # this package calls returns 204, so keeping the branch is harmless and
  # protects anyone still probing v2 behavior. Revisit for removal.
  if (status == 204 || status == 429) {
    hdr <- resp_header(resp, "retry-after")
    retry_after <- suppressWarnings(as.numeric(hdr))
    if (!length(retry_after) || is.na(retry_after)) retry_after <- 60
    stop(virustotal_rate_limit_error(
      message = "Rate limit exceeded. Only 4 requests per minute allowed.",
      retry_after = retry_after
    ))
  }

  if (status < 400) return(invisible())

  if (status == 401 || status == 403) {
    stop(virustotal_auth_error(
      message = "Authentication failed. Please check your API key."
    ))
  }

  if (status == 404) {
    stop(virustotal_error(
      message = "Resource not found.",
      status_code = status,
      response = resp
    ))
  }

  if (status >= 500) {
    stop(virustotal_error(
      message = paste("VirusTotal server error:", status),
      status_code = status,
      response = resp
    ))
  }

  stop(virustotal_error(
    message = paste("HTTP request failed with status", status),
    status_code = status,
    response = resp
  ))
}

#' Encode a URL as a VirusTotal v3 URL identifier
#'
#' The API identifies a URL by its unpadded URL-safe base64 encoding, i.e.
#' \code{base64.urlsafe_b64encode(url).strip("=")}. The standard base64
#' alphabet is not interchangeable: a \code{/} in the identifier would be read
#' as a path separator and the request would address no endpoint.
#'
#' @param url A character string containing the URL.
#' @return A character string containing the URL identifier.
#' @keywords internal
vt_url_id <- function(url) {
  chartr("+/", "-_", gsub("=+$", "", base64_encode(charToRaw(url))))
}
