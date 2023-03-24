package common

// Semaphore allows N threads to acquire at the same time
type Semaphore struct {
	channel chan struct{}
}

// NewSemaphore constructs a new semaphore that is initialized
func NewSemaphore(n int) Semaphore {
	res := Semaphore{channel: make(chan struct{}, n)}
	for i := 0; i < n; i++ {
		res.channel <- struct{}{}
	}
	return res
}

// Close kills the semaphore
func (s *Semaphore) Close() {
	close(s.channel)
}

// Acquire wait for the semaphore to be freed
func (s *Semaphore) Acquire() {
	<-s.channel
}

// Release frees the semaphore
func (s *Semaphore) Release() {
	s.channel <- struct{}{}
}
