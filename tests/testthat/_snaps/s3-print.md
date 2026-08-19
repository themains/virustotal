# print.virustotal_file_report output is stable

    Code
      print(fake_file_report())
    Output
      VirusTotal API Response
      ======================
      
      Type: File Report 
      ID: 99017f6eebbac24f351415dd410d522d 
      Resource Type: file 
      
      Detection Summary:
        Malicious: 2
        Suspicious: 1
        Undetected: 60
        Harmless: 0
      
      File Size: 68 bytes
      SHA256: ababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
      

# print.virustotal_domain_report output is stable

    Code
      print(report)
    Output
      VirusTotal API Response
      ======================
      
      Type: Domain Report 
      ID: example.com 
      Resource Type: domain 
      
      Domain Reputation:
        Malicious: 0
        Suspicious: 0
        Undetected: 25
        Harmless: 68
      
      Categories: Vendor A, Vendor B 
      

# summary.virustotal_response lists malicious engines

    Code
      summary(fake_file_report())
    Output
      VirusTotal API Response
      ======================
      
      Type: File Report 
      ID: 99017f6eebbac24f351415dd410d522d 
      Resource Type: file 
      
      Detection Summary:
        Malicious: 2
        Suspicious: 1
        Undetected: 60
        Harmless: 0
      
      File Size: 68 bytes
      SHA256: ababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
      
      Engines detecting as malicious:
        - EngineA
        - EngineB
      

# print.virustotal_error output is stable

    Code
      print(virustotal_error("Resource not found.", status_code = 404))
    Output
      VirusTotal API Error: Resource not found.
      HTTP Status Code: 404
    Code
      print(virustotal_rate_limit_error("Rate limit exceeded.", retry_after = 37))
    Output
      VirusTotal API Error: Rate limit exceeded.
      Retry after: 37 seconds
    Code
      print(virustotal_validation_error("Bad input.", parameter = "hash"))
    Output
      VirusTotal API Error: Bad input.
      Parameter: hash

