//go:build js && wasm

package bridge

import (
	"syscall/js"

	webgpubridge "github.com/consensys/gnark/backend/accelerated/webgpu/internal/bridge"
)

var Bridge = Groth16Client{Client: webgpubridge.NewClient("gnarkGroth16WebGPU", "webgpu groth16")}

type Groth16Client struct {
	webgpubridge.Client
}

type MSMBatchResult struct {
	G1ABytes []byte
	G1BBytes []byte
	G1KBytes []byte
	G2BBytes []byte
}

func JSUint8Array(src []byte) js.Value {
	return webgpubridge.JSUint8Array(src)
}

func JSObject() js.Value {
	return webgpubridge.JSObject()
}

func (c Groth16Client) MSMG1(handle, vectorName string, scalarsPacked []byte) ([]byte, error) {
	value, err := c.CallPromise("msmG1", handle, vectorName, webgpubridge.JSUint8Array(scalarsPacked))
	if err != nil {
		return nil, err
	}
	return webgpubridge.GoBytes(c.ErrorPrefix, value)
}

func (c Groth16Client) MSMBatch(handle string, g1A, g1B, g1K []byte) (MSMBatchResult, error) {
	payload := webgpubridge.JSObject()
	payload.Set("g1A", webgpubridge.JSUint8Array(g1A))
	payload.Set("g1B", webgpubridge.JSUint8Array(g1B))
	payload.Set("g1K", webgpubridge.JSUint8Array(g1K))
	value, err := c.CallPromise("msmBatch", handle, payload)
	if err != nil {
		return MSMBatchResult{}, err
	}
	result := MSMBatchResult{}
	if result.G1ABytes, err = webgpubridge.GoBytes(c.ErrorPrefix, value.Get("g1A")); err != nil {
		return MSMBatchResult{}, err
	}
	if result.G1BBytes, err = webgpubridge.GoBytes(c.ErrorPrefix, value.Get("g1B")); err != nil {
		return MSMBatchResult{}, err
	}
	if result.G1KBytes, err = webgpubridge.GoBytes(c.ErrorPrefix, value.Get("g1K")); err != nil {
		return MSMBatchResult{}, err
	}
	if result.G2BBytes, err = webgpubridge.GoBytes(c.ErrorPrefix, value.Get("g2B")); err != nil {
		return MSMBatchResult{}, err
	}
	return result, nil
}

func (c Groth16Client) ComputeHZMSMG1(handle string, aPacked, bPacked, cPacked []byte) ([]byte, error) {
	value, err := c.CallPromise(
		"computeHZMSMG1",
		handle,
		webgpubridge.JSUint8Array(aPacked),
		webgpubridge.JSUint8Array(bPacked),
		webgpubridge.JSUint8Array(cPacked),
	)
	if err != nil {
		return nil, err
	}
	return webgpubridge.GoBytes(c.ErrorPrefix, value)
}

func (c Groth16Client) PrewarmQuotientDomain(curve string, domainSize int) error {
	_, err := c.CallPromise("prewarmQuotientDomain", curve, domainSize)
	return err
}
