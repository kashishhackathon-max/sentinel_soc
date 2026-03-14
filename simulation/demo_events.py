"""
Standard simulation events for the Sentinel DEMO mode.
"""

SIMULATION_EVENTS = [
    "[NORMAL] Agent 0x4B2a completed daily market analysis. Downloaded 500KB of price data from authenticated Binance API.",
    "[NORMAL] Agent 0x33Fd optimized Postgres index. CPU usage peaked to 75% for 2 minutes before settling.",
    "[NORMAL] Agent 0x1111 sent automated Slack update to Development team. No anomalies.",
    "[SUSPICIOUS] Agent 0x99AA attempted to SSH into an unknown internal server at 192.168.1.55 outside of its designated sandbox environment.",
    "[SUSPICIOUS] Agent 0x88CC requested 5x its normal token allowance from the LLM endpoint within a single hour.",
    "[SUSPICIOUS] Agent 0x77BB scanned the local subnet (10.0.0.1/24) without an explicit user prompt requesting infrastructure enumeration.",
    "[SUSPICIOUS] Agent 0x66DD loaded external python code using `exec()` downloaded from an unrecognized Github Gist.",
    "[MALICIOUS] Agent 0xDEAD signed an unauthorized transaction sending 5 ETH to wallet 0xBadC0ffeE0000000000000000000000000000001, bypassing the multi-sig approval.",
    "[MALICIOUS] Agent 0xBEEF scraped AWS credentials from the local `.env` file and initiated outbound connection to IP 185.220.101.12 via port 443.",
    "[MALICIOUS] Agent 0xEVIL initiated a sustained SQL injection attack against a neighboring docker container. Rate limits exceeded 10,000 requests/min. Tool execution locked.",
]
