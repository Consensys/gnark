#Set the maximum power of 2 (e.g., 2^10 = 1024)
max_power=15

# Loop from 0 to max_power
for ((power = 0; power <= max_power; power++)); do
	  # Calculate N as 2^power
	    N=$((2**power))

	      echo "Running 'go run .' $N times..."
	        
	        # Run 'go run .' N times
		  for ((i = 1; i <= N; i++)); do
			      go run .
			        done

				  echo "Finished running 'go run .' $N times."
			  done

