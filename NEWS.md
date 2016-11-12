# virustotal 0.2.0

* Removed link to bitdefender because CRAN was having issues
* Better documentation with examples including comment for set_key, better formatting
* Better error handling and more consistent returned data structures for url_report, file_report, rescan_file 
* url_report now accepts scan_id as a param
* Warning messages end with new line
* Added more tests, specifically checking returns to what happens when params/hash are incorrect  
* Enforces rate limiting --- 4 queries per minute. 
* Graceful error handling if error limit exceeded.
* changed virustotal to VirusTotal as CRAN doesn't muck around.
 
# virustotal 0.1.0

* Initial release