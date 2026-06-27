//go:build cuda

package p2

/*
#include <stddef.h>
int   gpu_device_sync(void);
int   gpu_mem_get_info(size_t* free_bytes, size_t* total_bytes);
void* gpu_event_create(void);
void  gpu_event_record(void* event, void* stream);
void  gpu_stream_wait_event(void* stream, void* event);
void  gpu_event_destroy(void* event);
void* gpu_stream_create(void);
void  gpu_stream_sync(void* stream);
void  gpu_stream_destroy(void* stream);
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

// StreamID indexes the device's fixed stream set. StreamCompute is the default
// (NULL) stream; the others are created lazily for the m6 overlap milestone.
type StreamID int

// EventID indexes the device's fixed event set.
type EventID int

const (
	StreamCompute  StreamID = 0 // default stream (NULL handle)
	StreamTransfer StreamID = 1
	StreamMSM      StreamID = 2

	maxStreams = 4
	maxEvents  = 16
)

// Device owns the CUDA stream/event handles for one prove and binds the calling
// OS thread to the GPU. For milestones m0–m5 everything runs on StreamCompute
// (the default stream); StreamTransfer/StreamMSM + events are populated in m6.
type Device struct {
	streams [maxStreams]unsafe.Pointer // [StreamCompute]=nil (default stream)
	events  [maxEvents]unsafe.Pointer
}

// NewDevice binds the GPU on the calling thread and returns a Device. The caller
// should keep using the same OS thread (each FrVector op re-binds defensively).
func NewDevice() (*Device, error) {
	if !gpu.Available() {
		return nil, fmt.Errorf("p2: no CUDA device available")
	}
	gpu.SetDevice()
	return &Device{}, nil
}

// Bind pins the calling goroutine to its OS thread and selects this GPU. Callers
// that issue a run of device ops should Bind once and defer Unbind.
func (d *Device) Bind() {
	runtime.LockOSThread()
	gpu.SetDevice()
}

// Unbind releases the OS-thread pin established by Bind.
func (d *Device) Unbind() { runtime.UnlockOSThread() }

// stream returns the CUDA handle for a StreamID (NULL for StreamCompute).
func (d *Device) stream(id StreamID) unsafe.Pointer {
	if int(id) < 0 || int(id) >= maxStreams {
		return nil
	}
	return d.streams[id]
}

// Sync blocks until all device work completes.
func (d *Device) Sync() error {
	if C.gpu_device_sync() != 0 {
		return fmt.Errorf("p2: device sync failed")
	}
	return nil
}

// SyncStream blocks until the given stream drains.
func (d *Device) SyncStream(id StreamID) {
	C.gpu_stream_sync(d.stream(id))
}

// MemGetInfo returns free and total device memory in bytes.
func (d *Device) MemGetInfo() (free, total uint64, err error) {
	var f, t C.size_t
	if C.gpu_mem_get_info(&f, &t) != 0 {
		return 0, 0, fmt.Errorf("p2: mem_get_info failed")
	}
	return uint64(f), uint64(t), nil
}

// EnsureStreams lazily creates StreamTransfer/StreamMSM (m6). Idempotent.
func (d *Device) EnsureStreams() {
	for id := StreamTransfer; int(id) < maxStreams; id++ {
		if d.streams[id] == nil {
			d.streams[id] = C.gpu_stream_create()
		}
	}
}

// RecordEvent records event e on stream s (m6 cross-stream ordering).
func (d *Device) RecordEvent(s StreamID, e EventID) {
	if d.events[e] == nil {
		d.events[e] = C.gpu_event_create()
	}
	C.gpu_event_record(d.events[e], d.stream(s))
}

// WaitEvent makes stream s wait until event e is recorded.
func (d *Device) WaitEvent(s StreamID, e EventID) {
	if d.events[e] == nil {
		return
	}
	C.gpu_stream_wait_event(d.stream(s), d.events[e])
}

// Close releases the streams and events owned by the Device.
func (d *Device) Close() {
	for i := range d.events {
		if d.events[i] != nil {
			C.gpu_event_destroy(d.events[i])
			d.events[i] = nil
		}
	}
	for i := StreamTransfer; int(i) < maxStreams; i++ {
		if d.streams[i] != nil {
			C.gpu_stream_destroy(d.streams[i])
			d.streams[i] = nil
		}
	}
}
