ZscalerAIGuard_CL
| where TimeGenerated > ago(1d)
// proxy mode: user looks like a real email or username, not Claude Code's JSON
| where isnotempty(user_s) and user_s !startswith "{"
| where detectionDetails_prompt_injection_triggered_b == true
     or detectionDetails_malicious_url_triggered_b == true
// exclude offensive security (fill in their real identifiers)
| where user_s !in ("redteam1@company.com", "redteam2@company.com")
| summarize Hits = count(),
            Injection = countif(detectionDetails_prompt_injection_triggered_b == true),
            MaliciousURL = countif(detectionDetails_malicious_url_triggered_b == true),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
            by user_s
| where Hits >= 3
