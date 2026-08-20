# Replaying a fixture still goes through vt_key(), which errors before
# httptest2 ever intercepts the request -- so a keyless machine (CI, CRAN)
# needs a placeholder. Only fills one in when none is set, so re-recording
# against the live API keeps using the real key.
local_key_for_replay <- function(env = parent.frame()) {
  if (!has_vt_key()) {
    withr::local_envvar(
      c(VIRUSTOTAL_API_KEY = strrep("a", 64)),
      .local_envir = env
    )
  }
  invisible(NULL)
}
