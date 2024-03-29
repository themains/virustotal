% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/get_domain_relationship.R
\name{get_domain_relationship}
\alias{get_domain_relationship}
\title{Retrieve related objects to an Internet domain}
\usage{
get_domain_relationship(
  domain = NULL,
  relationship = "subdomains",
  limit = NULL,
  cursor = NULL,
  ...
)
}
\arguments{
\item{domain}{domain name. String. Required.}

\item{relationship}{relationship name. String. Required. Default is \code{subdomains}. 
For all the options see \url{https://developers.virustotal.com/v3.0/reference#domains-relationships}}

\item{limit}{Number of entries. Integer. Optional.  Default is 10.}

\item{cursor}{String. Optional.}

\item{\dots}{Additional arguments passed to \code{\link{virustotal_GET}}.}
}
\value{
named list
}
\description{
Retrieve related objects to an Internet domain
}
\examples{
\dontrun{

# Before calling the function, set the API key using set_key('api_key_here')
   
get_domain_relationship("https://www.google.com")
get_domain_relationship("https://www.goodsfwrfw.com") # Domain not found
}
}
\references{
\url{https://developers.virustotal.com/v2.0/reference}
}
\seealso{
\code{\link{set_key}} for setting the API key
}
