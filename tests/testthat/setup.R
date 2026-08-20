# The client-side throttle would make mocked replays sleep between requests;
# nothing in the suite touches the network, so pacing protects nothing here.
# The integration test re-enables it locally.
old_throttle <- options(virustotal.throttle = FALSE)
withr::defer(options(old_throttle), teardown_env())
