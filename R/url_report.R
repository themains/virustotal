#' Get URL Report
#'
#' Retrieve a scan report for a given URL. If no scan report is available, set \code{scan} to \code{1} to get a new report.
#' 
#' @param url URL. String. \code{url} or \code{scan_id} must be specified.
#' @param scan_id scan id for a particular url scan. String. \code{url} or \code{scan_id} must be specified.
#' @param scan String. Optional. Can be 0 or 1. Default is \code{1}. 
#' When \code{1}, submits \code{url} for scanning if no existing reports are found. 
#' When scan is set to \code{1}, the result includes a \code{scan_id} field, which can be used again to retrieve the report. 
#' @param \dots Additional arguments passed to \code{\link{virustotal2_GET}}.
#'  
#' @return data.frame with 13 columns: 
#' \code{scan_id, resource, url, response_code, scan_date, permalink, verbose_msg, positives, total, .id, detected, result, detail}
#'  
#' @export
#' 
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' 
#' @seealso \code{\link{set_key}} for setting the API key
#'
#' @examples \dontrun{
#' 
#' # Before calling the function, set the API key using set_key('api_key_here')
#' 
#' url_report("http://www.google.com")
#' url_report(scan_id = "ebdd15c397d2b0c6f50c3f2df531357d1201ff5976802316405e60880d6bf5ec-1478786749")
#' }

url_report <- function(url = NULL, scan_id = NULL, scan = 1, ...) {

  if (!is.character(url) & !is.character(scan_id)) {
        stop("Must specify url or scan_id.\n")
  }

  if (! (scan %in% c("0", "1"))) stop("scan must be either 0 or 1.\n")

  params <- list(resource = url, scan_id = scan_id, scan = scan)

  .Deprecated("")

  res    <- virustotal2_POST(path = "url/report", query = params, ...)

  # Initialize empty data.frame
  res_df <- read.table(text = "", col.names = c("scan_id", "resource", "url",
                                                "response_code", "scan_date",
                                                "permalink", "verbose_msg",
                                                "positives", "total",
                                                "detected", "result",
                                                "detail"))

  if ( !is.null(scan_id) & length(res) == 0) {
    warning("No results returned. Likely cause: incorrect scan_id.\n")
    res_df[1, "scan_id"] <- scan_id
    return(res_df)

  } else if (res$response_code == 0) {
    warning("No reports for the URL available. Set scan to 1 to submit URL
                                                               for scanning.\n")
    res_df[1, match(names(res), names(res_df))] <- res
    return(res_df)

  } else if (!is.null(url) & length(res) < 11) {
      warning("No reports for the URL available. The URL has been successfully
                        submitted for scanning. Come back later for results.\n")
      res_df[1, match(names(res), names(res_df))] <- res
      return(res_df)
    }

    res_10 <- do.call(cbind, lapply(res[1:10], unlist))
    res_11 <- ldply(res$scans, as.data.frame)
    cbind(res_10, res_11)
}
