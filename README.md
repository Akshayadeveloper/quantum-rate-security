# quantum-rate-security
<b>Focus: </b>Non-linear detection of slow-burn, sophisticated API attack patterns.

<b>Core Problem Solved: </b>

Standard rate limiters only count simple requests per time window. QuantumRate uses advanced statistical analysis (moving average and standard deviation) to detect subtle, distributed, and slow-burn Denial of Service (DoS) attacks, such as those that slowly increment usage across thousands of IPs to avoid detection. This involves analyzing the variability and pattern change of requests, not just the raw count.

<b>The Solution Mechanism (Python): </b>

A Python class that tracks request metrics and uses a statistical anomaly detection method (Z-score based on moving average and standard deviation) to flag users exhibiting unusual pattern shifts.
