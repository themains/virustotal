structure(list(method = "GET", url = "https://www.virustotal.com/api/v3/files/0123456789abcdef0123456789abcdef", 
    status_code = 404L, headers = structure(list(`content-type` = "application/json", 
        vary = "Accept-Encoding", `content-encoding` = "gzip", 
        `x-cloud-trace-context` = "cfd08c5bfec301e8db3295d185ceb9e1", 
        date = "Wed, 19 Aug 2026 15:33:50 GMT", server = "Google Frontend", 
        `content-length` = "105", via = "1.1 google", `alt-svc` = "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000"), class = "httr2_headers"), 
    body = charToRaw("{\"error\": {\"code\": \"NotFoundError\", \"message\": \"File \\\"0123456789abcdef0123456789abcdef\\\" not found\"}}"), 
    timing = c(redirect = 0, namelookup = 0, connect = 0, pretransfer = 0.00019, 
    starttransfer = 0.639618, total = 0.639727), cache = new.env(parent = emptyenv())), class = "httr2_response")
