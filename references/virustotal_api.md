# VirusTotal API Notes

Use VT v3 domain endpoint:
- GET https://www.virustotal.com/api/v3/domains/{domain}
- Header: x-apikey: <VT_API_KEY>

Response field used for risk summary:
- data.attributes.last_analysis_stats
  - malicious, suspicious, harmless, undetected, timeout

Rate limits vary by plan. Use a small delay between requests when needed.

Common HTTP codes:
- 200 OK
- 401 Unauthorized (missing/invalid API key)
- 429 Too Many Requests (rate limit)
