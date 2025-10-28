from collections import deque
import math
import time
from typing import Dict, Deque, List

# Configuration for the statistical window
WINDOW_SIZE = 10 
# Z-score threshold for anomaly detection (e.g., 2.5 means 2.5 standard deviations away)
ANOMALY_THRESHOLD = 2.5 

class QuantumRateLimiter:
    def __init__(self, user_id: str):
        self.user_id = user_id
        # Deque to store the last N request counts per interval (e.g., per 1 second)
        self.request_history: Deque[int] = deque(maxlen=WINDOW_SIZE)
        self.last_interval_end = time.time()
        self.current_interval_count = 0
        
        # Initial state to avoid false positives on startup
        for _ in range(WINDOW_SIZE):
            self.request_history.append(1) 

    def _update_history(self):
        """Pushes the current interval count to history and resets the counter."""
        self.request_history.append(self.current_interval_count)
        self.current_interval_count = 0
        self.last_interval_end = time.time()

    def _calculate_statistics(self) -> Dict[str, float]:
        """Calculates Moving Average (MA) and Standard Deviation (SD)."""
        if not self.request_history:
            return {"ma": 0.0, "sd": 0.0}

        history = list(self.request_history)
        ma = sum(history) / len(history)
        
        variance = sum((x - ma) ** 2 for x in history) / len(history)
        sd = math.sqrt(variance)
        
        return {"ma": ma, "sd": sd}

    def check_request(self) -> bool:
        """
        The core rate-limiting and anomaly detection check.
        Returns True if request is safe, False if attack is detected.
        """
        # 1. Update interval count
        self.current_interval_count += 1
        
        # 2. Check if a new interval has started (e.g., 1 second interval)
        if time.time() - self.last_interval_end >= 1.0:
            self._update_history()
            
            # 3. Calculate MA and SD on the new history
            stats = self._calculate_statistics()
            ma = stats['ma']
            sd = stats['sd']
            
            # 4. Anomaly Detection (Z-Score)
            # A request count is anomalous if it is too many standard deviations away 
            # from the recent moving average (MA).
            if sd > 0: # Avoid division by zero
                z_score = abs(self.current_interval_count - ma) / sd
                
                if z_score > ANOMALY_THRESHOLD:
                    print(f"🚨 ATTACK DETECTED for {self.user_id}! Z-Score: {z_score:.2f}")
                    print(f"    Current Count ({self.current_interval_count}) is far from MA ({ma:.2f}).")
                    return False # Block the request
        
        # 5. Safe: Allow the request
        return True


# --- Demonstration ---

attacker_id = "192.168.1.100"
rate_limiter = QuantumRateLimiter(attacker_id)

print("--- Phase 1: Normal Traffic (1-2 reqs/sec) ---")
for i in range(10):
    rate_limiter.current_interval_count = 1 # Simulate 1 request per second
    time.sleep(0.1) # Time passes for the counter to update

# --- Phase 2: Slow-Burn Attack Starts (5 reqs/sec) ---
print("\n--- Phase 2: Detecting Slow-Burn Attack (5 reqs/sec) ---")
# The average is suddenly and consistently jumped up, but not high enough 
# for a simple fixed limit to catch it (e.g., if the limit was 10).
for i in range(5):
    rate_limiter.current_interval_count = 5 
    # Must wait for the interval to elapse to push the new, high count to history
    time.sleep(1.0) 
    if not rate_limiter.check_request():
        break
    
# --- Phase 3: Sudden Spike (Classic DDoS) ---
print("\n--- Phase 3: Sudden Spike ---")
# Simulating a massive, sudden jump in traffic
rate_limiter.current_interval_count = 50 
if not rate_limiter.check_request():
    print(f"Blocked spike attack on {attacker_id}!")
      
