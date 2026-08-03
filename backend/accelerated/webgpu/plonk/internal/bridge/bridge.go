//go:build js && wasm

package bridge

import (
	"syscall/js"

	webgpubridge "github.com/consensys/gnark/backend/accelerated/webgpu/internal/bridge"
)

var Bridge = Client{Client: webgpubridge.NewClient("gnarkPlonkWebGPU", "webgpu plonk")}

type Client struct {
	webgpubridge.Client
}

func JSUint8Array(src []byte) js.Value {
	return webgpubridge.JSUint8Array(src)
}

func JSObject() js.Value {
	return webgpubridge.JSObject()
}

func (c Client) MSMG1Slice(handle, vectorName string, start, count int, scalarsPacked []byte) ([]byte, error) {
	value, err := c.CallPromise(
		"msmG1",
		handle,
		vectorName,
		webgpubridge.JSUint8Array(scalarsPacked),
		start,
		count,
	)
	if err != nil {
		return nil, err
	}
	return webgpubridge.GoBytes(c.ErrorPrefix, value)
}

func (c Client) MSMG1Batch(handle, vectorName string, start, termsPerInstance, instanceCount int, scalarsPacked []byte) ([]byte, error) {
	value, err := c.CallPromise(
		"msmG1Batch",
		handle,
		vectorName,
		webgpubridge.JSUint8Array(scalarsPacked),
		start,
		termsPerInstance,
		instanceCount,
	)
	if err != nil {
		return nil, err
	}
	return webgpubridge.GoBytes(c.ErrorPrefix, value)
}

func (c Client) CanonicalizeQuotientVectors(curve string, valuesPacked []byte, vectorCount, elementCount int, inputBitReversed, inverseCoset bool) ([]byte, error) {
	value, err := c.CallPromise(
		"canonicalizeQuotientVectors",
		curve,
		webgpubridge.JSUint8Array(valuesPacked),
		vectorCount,
		elementCount,
		inputBitReversed,
		inverseCoset,
	)
	if err != nil {
		return nil, err
	}
	return webgpubridge.GoBytes(c.ErrorPrefix, value)
}

func (c Client) LagrangeQuotientVectors(curve string, valuesPacked []byte, vectorCount, elementCount int) ([]byte, error) {
	value, err := c.CallPromise(
		"lagrangeQuotientVectors",
		curve,
		webgpubridge.JSUint8Array(valuesPacked),
		vectorCount,
		elementCount,
	)
	if err != nil {
		return nil, err
	}
	return webgpubridge.GoBytes(c.ErrorPrefix, value)
}

func (c Client) TransformAndEvaluateQuotientCosets(
	curve string,
	dynamicValuesPacked, scalingPacked, staticValuesPacked, staticMontCacheKeysPacked, twiddlesPacked, denominatorsPacked, blindsPacked, scalarsPacked []byte,
	elementCount, blindCoeffCount, commitmentCount, dynamicTransformCacheKey, cosetCount, auxMontCacheKey int,
) ([]byte, error) {
	value, err := c.CallPromise(
		"transformAndEvaluateQuotientCosets",
		curve,
		webgpubridge.JSUint8Array(dynamicValuesPacked),
		webgpubridge.JSUint8Array(scalingPacked),
		webgpubridge.JSUint8Array(staticValuesPacked),
		webgpubridge.JSUint8Array(staticMontCacheKeysPacked),
		webgpubridge.JSUint8Array(twiddlesPacked),
		webgpubridge.JSUint8Array(denominatorsPacked),
		webgpubridge.JSUint8Array(blindsPacked),
		webgpubridge.JSUint8Array(scalarsPacked),
		elementCount,
		blindCoeffCount,
		commitmentCount,
		dynamicTransformCacheKey,
		cosetCount,
		auxMontCacheKey,
	)
	if err != nil {
		return nil, err
	}
	return webgpubridge.GoBytes(c.ErrorPrefix, value)
}

func (c Client) PreloadQuotientStaticAndAux(
	curve string,
	staticValuesPacked, staticMontCacheKeysPacked, scalingPacked, twiddlesPacked, denominatorsPacked []byte,
	elementCount, staticVectorCount, cosetCount, auxMontCacheKey int,
) error {
	_, err := c.CallPromise(
		"preloadQuotientStaticAndAux",
		curve,
		webgpubridge.JSUint8Array(staticValuesPacked),
		webgpubridge.JSUint8Array(staticMontCacheKeysPacked),
		webgpubridge.JSUint8Array(scalingPacked),
		webgpubridge.JSUint8Array(twiddlesPacked),
		webgpubridge.JSUint8Array(denominatorsPacked),
		elementCount,
		staticVectorCount,
		cosetCount,
		auxMontCacheKey,
	)
	return err
}

func (c Client) PrewarmQuotientTransformDomain(curve string, elementCount int) error {
	_, err := c.CallPromise("prewarmQuotientTransformDomain", curve, elementCount)
	return err
}

func (c Client) PrewarmQuotientCanonicalizeDomain(curve string, elementCount int) error {
	_, err := c.CallPromise("prewarmQuotientCanonicalizeDomain", curve, elementCount)
	return err
}

func (c Client) PrewarmQuotientEvaluateKernel(curve string, commitmentCount int) error {
	_, err := c.CallPromise("prewarmQuotientEvaluateKernel", curve, commitmentCount)
	return err
}
