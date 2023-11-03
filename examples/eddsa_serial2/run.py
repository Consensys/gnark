#!/opt/conda/bin/python

import subprocess
import re

# Set the maximum power of 2 (e.g., 2^10 = 1024)
max_power = 10
total_time = 0.0

# Loop from 0 to max_power
for power in range(max_power + 1):
    # Calculate N as 2^power
    N = 2 ** power

    print(f"Running 'go run .' {N} times...")

    # Initialize total_time_power for each power of 2
    total_time_power = 0.0

    # Run 'go run .' N times
    for i in range(N):
        # Run 'go run .' and capture its output
        process = subprocess.Popen("go run .", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        # Combine both stdout and stderr to ensure we capture the "took" value
        output = stdout + stderr

        # Use a regular expression to extract the "took" value
        match = re.search(r"took=([\d.]+)", output)
        
        if match:
            took = float(match.group(1))
            total_time_power += took

    print(f"Finished running 'go run .' {N} times. Total time: {total_time_power:.2f} seconds.")

    # Add total_time_power to the total_time
    total_time += total_time_power

print(f"Total time for all runs: {total_time:.2f} seconds.")

