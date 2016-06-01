#' Get Domain Report
#'
#' Retrieves report on a given domain, including passive DNS, urls detected by at least one url scanner. 
#' Gives category of the domain from \url{http://www.bitdefender.com/}
#' 
#' @param domain domain name (string)
#' @param \dots Additional arguments passed to \code{\link{virustotal_GET}}.
#' 
#' @return data.frame
#'  
#' @export
#' @references \url{https://www.virustotal.com/en/documentation/public-api/}
#' @examples \dontrun{
#' domain_report("http://www.google.com")
#' }

domain_report <- function(domain = NULL, ...) {

    if (!is.character(domain)) {
        stop("Must specify domain")
    }

    params <- list(domain = domain)

    res   <- virustotal_GET(path="domain/report", query = params, ...)

    res
}

