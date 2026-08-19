# A standing guard on the recorded fixtures.
#
# httptest2 writes response bodies only, so the x-apikey header should never
# reach disk -- but "should never" is what a test is for. This one fails if
# a re-recording ever writes the live key into a fixture, which is the
# moment it would otherwise be committed and pushed.

test_that("no fixture contains the API key", {
  key <- Sys.getenv("VIRUSTOTAL_API_KEY")
  if (!nzchar(key)) key <- Sys.getenv("VirustotalToken")
  skip_if(!nzchar(key), "No key set; nothing to search for")

  files <- list.files("_fixtures", recursive = TRUE, full.names = TRUE)
  skip_if(!length(files), "No fixtures recorded")

  leaked <- Filter(
    function(f) any(grepl(key, readLines(f, warn = FALSE), fixed = TRUE)),
    files
  )
  expect_equal(leaked, list())
})
