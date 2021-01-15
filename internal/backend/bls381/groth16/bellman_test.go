package groth16

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	curve "github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tests and benchmarks adapted from https://github.com/esuwu/groth16-verifier-bls12381
func TestVeriyBellmanProof(t *testing.T) {
	for _, test := range []struct {
		vk     string
		proof  string
		inputs string
		ok     bool
	}{
		{"hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r",
			"lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF",
			"LcMT3OOlkHLzJBKCKjjzzVMg+r+FVgd52LlhZPB4RFg=",
			true},

		{"hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r",
			"lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF",
			"cmzVCcRVnckw3QUPhmG4Bkppeg4K50oDQwQ9EH+Fq1s=",
			false},

		{"hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r",
			"lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF",
			"cmzVCcRVnckw3QUPhmG4Bkppeg4K50oDQwQ9EH+Fq1s=",
			false},

		{"kYYCAS8vM2T99GeCr4toQ+iQzvl5fI89mPrncYqx3C1d75BQbFk8LMtcnLWwntd6knkzSwcsialcheg69eZYPK8EzKRVI5FrRHKi8rgB+R5jyPV70ejmYEx1neTmfYKODRmARr/ld6pZTzBWYDfrCkiS1QB+3q3M08OQgYcLzs/vjW4epetDCmk0K1CEGcWdh7yLzdqr7HHQNOpZI8mdj/7lR0IBqB9zvRfyTr+guUG22kZo4y2KINDp272xGglKEeTglTxyDUriZJNF/+T6F8w70MR/rV+flvuo6EJ0+HA+A2ZnBbTjOIl9wjisBV+0jgld4oAppAOzvQ7eoIx2tbuuKVSdbJm65KDxl/T+boaYnjRm3omdETYnYRk3HAhrAeWpefX+dM/k7PrcheInnxHUyjzSzqlN03xYjg28kdda9FZJaVsQKqdEJ/St9ivXlp7+dPDIOfm77haSFnvr33VwYH/KbIalfOJPRvBLzqlHD8BxunNebMr6Gr6S+u+n",
			"sStVLdyxqInmv76iaNnRFB464lGq48iVeqYWSi2linE9DST0fTNhxSnvSXAoPpt8tFsanj5vPafC+ij/Fh98dOUlMbO42bf280pOZ4lm+zr63AWUpOOIugST+S6pq9zeB0OHp2NY8XFmriOEKhxeabhuV89ljqCDjlhXBeNZwM5zti4zg89Hd8TbKcw46jAsjIJe2Siw3Th7ELQQKR5ucX50f0GISmnOSceePPdvjbGJ8fSFOnSmSp8dK7uyehrU",
			"",
			true},

		{"mY//hEITCBCZUJUN/wsOlw1iUSSOESL6PFSbN1abGK80t5jPNICNlPuSorio4mmWpf+4uOyv3gPZe54SYGM4pfhteqJpwFQxdlpwXWyYxMTNaSLDj8VtSn/EJaSu+P6nFmWsda3mTYUPYMZzWE4hMqpDgFPcJhw3prArMThDPbR3Hx7E6NRAAR0LqcrdtsbDqu2T0tto1rpnFILdvHL4PqEUfTmF2mkM+DKj7lKwvvZUbukqBwLrnnbdfyqZJryzGAMIa2JvMEMYszGsYyiPXZvYx6Luk54oWOlOrwEKrCY4NMPwch6DbFq6KpnNSQwOpgRYCz7wpjk57X+NGJmo85tYKc+TNa1rT4/DxG9v6SHkpXmmPeHhzIIW8MOdkFjxB5o6Qn8Fa0c6Tt6br2gzkrGr1eK5/+RiIgEzVhcRrqdY/p7PLmKXqawrEvIv9QZ3ijytPNwinlC8XdRLO/YvP33PjcI9WSMcHV6POP9KPMo1rngaIPMegKgAvTEouNFKp4v3wAXRXX5xEjwXAmM5wyB/SAOaPPCK/emls9kqolHsaj7nuTTbrvSV8bqzUwzQ",
			"g53N8ecorvG2sDgNv8D7quVhKMIIpdP9Bqk/8gmV5cJ5Rhk9gKvb4F0ll8J/ZZJVqa27OyciJwx6lym6QpVK9q1ASrqio7rD5POMDGm64Iay/ixXXn+//F+uKgDXADj9AySri2J1j3qEkqqe3kxKthw94DzAfUBPncHfTPazVtE48AfzB1KWZA7Vf/x/3phYs4ckcP7ZrdVViJVLbUgFy543dpKfEH2MD30ZLLYRhw8SatRCyIJuTZcMlluEKG+d",
			"aZ8tqrOeEJKt4AMqiRF/WJhIKTDC0HeDTgiJVLZ8OEs=",
			true},

		{"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",
			true},

		{"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",
			true},

		{"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",
			true},
		// grothFail from Scala
		{
			"lp7+dPDIOfm77haSFnvr33VwYH/KbIalfOJPRvBLzqlHD8BxunNebMr6Gr6S+u+nh7yLzdqr7HHQNOpZI8mdj/7lR0IBqB9zvRfyTr+guUG22kZo4y2KINDp272xGglKEeTglTxyDUriZJNF/+T6F8w70MR/rV+flvuo6EJ0+HA+A2ZnBbTjOIl9wjisBV+0iISo2JdNY1vPXlpwhlL2fVpW/WlREkF0bKlBadDIbNJBgM4niJGuEZDru3wqrGueETKHPv7hQ8em+p6vQolp7c0iknjXrGnvlpf4QtUtpg3z/D+snWjRPbVqRgKXWtihuIvPFaM6dt7HZEbkeMnXWwSINeYC/j3lqYnce8Jq+XkuF42stVNiooI+TuXECnFdFi9Ib25b9wtyz3H/oKg48He1ftntj5uIRCOBvzkFHGUF6Ty214v3JYvXJjdS4uS2jekplZYoV0aXEnYEOIvfF7d4xay3qkx2NspooM4HeZpiHknIWkUVhGVJBzBDLjLB",
			"jiGBK+TGHfH8Oadexhdet7ExyIWibSmamWQvffZkyl3WnMoVbTQ3lOks4Mca3sU5qgcaLyQQ1FjFW4g6vtoMapZ43hTGKaWO7bQHsOCvdwHCdwJDulVH16cMTyS9F0BfBJxa88F+JKZc4qMTJjQhspmq755SrKhN9Jf+7uPUhgB4hJTSrmlOkTatgW+/HAf5kZKhv2oRK5p5kS4sU48oqlG1azhMtcHEXDQdcwf9ANel4Z9cb+MQyp2RzI/3hlIx",
			"",
			false},
		{
			"lp7+dPDIOfm77haSFnvr33VwYH/KbIalfOJPRvBLzqlHD8BxunNebMr6Gr6S+u+nh7yLzdqr7HHQNOpZI8mdj/7lR0IBqB9zvRfyTr+guUG22kZo4y2KINDp272xGglKEeTglTxyDUriZJNF/+T6F8w70MR/rV+flvuo6EJ0+HA+A2ZnBbTjOIl9wjisBV+0iISo2JdNY1vPXlpwhlL2fVpW/WlREkF0bKlBadDIbNJBgM4niJGuEZDru3wqrGueETKHPv7hQ8em+p6vQolp7c0iknjXrGnvlpf4QtUtpg3z/D+snWjRPbVqRgKXWtihuIvPFaM6dt7HZEbkeMnXWwSINeYC/j3lqYnce8Jq+XkuF42stVNiooI+TuXECnFdFi9Ib25b9wtyz3H/oKg48He1ftntj5uIRCOBvzkFHGUF6Ty214v3JYvXJjdS4uS2jekplZYoV0aXEnYEOIvfF7d4xay3qkx2NspooM4HeZpiHknIWkUVhGVJBzBDLjLBjiGBK+TGHfH8Oadexhdet7ExyIWibSmamWQvffZkyl3WnMoVbTQ3lOks4Mca3sU5",
			"hp1iMepdu0rKoBh0NXcw9F9hkiggDIkRNINq2rlvUypPiSmp8U8tDSMeG0YVSovFteecr3THhBJj0qNeEe9jA2Ci64fKG9WT1heMYzEAQKebOErYXYCm9d72n97mYn1XBq+g1Y730XEDv4BIDI1hBDntJcgcj/cSvcILB1+60axJvtyMyuizxUr1JUBUq9njtmJ9m8zK6QZLNqMiKh0f2jokQb5mVhu6v5guW3KIjwQc/oFK/l5ehKAOPKUUggNh",
			"c9BSUPtO0xjPxWVNkEMfXe7O4UZKpaH/nLIyQJj7iA4=",
			false},
		{
			"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",
			false},
		{
			"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",
			false},
	} {
		// decode verifying key
		var bvk BellmanVerifyingKey
		var vk VerifyingKey

		vkBytes, err := base64.StdEncoding.DecodeString(test.vk)
		require.NoError(t, err)

		_, err = bvk.ReadFrom(bytes.NewReader(vkBytes))
		require.NoError(t, err)

		vk.FromBellmanVerifyingKey(&bvk)

		// decode proof
		proofBytes, err := base64.StdEncoding.DecodeString(test.proof)
		require.NoError(t, err)

		var proof Proof
		_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
		require.NoError(t, err)

		// decode inputs
		inputsBytes, err := base64.StdEncoding.DecodeString(test.inputs)
		require.NoError(t, err)
		inputs, err := decodeInputs(inputsBytes)
		require.NoError(t, err)

		// verify groth16 proof
		err = Verify(&proof, &vk, inputs)
		if test.ok {
			assert.NoError(t, err)
		}
	}
}

func decodeTestVector(vkTest, proofTest, inputsTest string) (proof Proof, vk VerifyingKey, witness []fr.Element, err error) {
	var vkBytes, proofBytes, inputBytes []byte
	if vkBytes, err = base64.StdEncoding.DecodeString(vkTest); err != nil {
		return
	}
	if proofBytes, err = base64.StdEncoding.DecodeString(proofTest); err != nil {
		return
	}
	if inputBytes, err = base64.StdEncoding.DecodeString(inputsTest); err != nil {
		return
	}
	if witness, err = decodeInputs(inputBytes); err != nil {
		return
	}
	if _, err = proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return
	}

	var bvk BellmanVerifyingKey
	if _, err = bvk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return
	}

	vk.FromBellmanVerifyingKey(&bvk)
	return
}

func BenchmarkGroth16Verify0inputsBLS(b *testing.B) {
	vkTest := "kYYCAS8vM2T99GeCr4toQ+iQzvl5fI89mPrncYqx3C1d75BQbFk8LMtcnLWwntd6knkzSwcsialcheg69eZYPK8EzKRVI5FrRHKi8rgB+R5jyPV70ejmYEx1neTmfYKODRmARr/ld6pZTzBWYDfrCkiS1QB+3q3M08OQgYcLzs/vjW4epetDCmk0K1CEGcWdh7yLzdqr7HHQNOpZI8mdj/7lR0IBqB9zvRfyTr+guUG22kZo4y2KINDp272xGglKEeTglTxyDUriZJNF/+T6F8w70MR/rV+flvuo6EJ0+HA+A2ZnBbTjOIl9wjisBV+0jgld4oAppAOzvQ7eoIx2tbuuKVSdbJm65KDxl/T+boaYnjRm3omdETYnYRk3HAhrAeWpefX+dM/k7PrcheInnxHUyjzSzqlN03xYjg28kdda9FZJaVsQKqdEJ/St9ivXlp7+dPDIOfm77haSFnvr33VwYH/KbIalfOJPRvBLzqlHD8BxunNebMr6Gr6S+u+n"
	proofTest := "sStVLdyxqInmv76iaNnRFB464lGq48iVeqYWSi2linE9DST0fTNhxSnvSXAoPpt8tFsanj5vPafC+ij/Fh98dOUlMbO42bf280pOZ4lm+zr63AWUpOOIugST+S6pq9zeB0OHp2NY8XFmriOEKhxeabhuV89ljqCDjlhXBeNZwM5zti4zg89Hd8TbKcw46jAsjIJe2Siw3Th7ELQQKR5ucX50f0GISmnOSceePPdvjbGJ8fSFOnSmSp8dK7uyehrU"
	inputsTest := ""

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, vk, witness, err := decodeTestVector(vkTest, proofTest, inputsTest)
		if err != nil {
			b.Fatal(err)
		}
		if err = Verify(&proof, &vk, witness); err != nil {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkGroth16Verify1inputsBLS(b *testing.B) {
	vkTest := "mY//hEITCBCZUJUN/wsOlw1iUSSOESL6PFSbN1abGK80t5jPNICNlPuSorio4mmWpf+4uOyv3gPZe54SYGM4pfhteqJpwFQxdlpwXWyYxMTNaSLDj8VtSn/EJaSu+P6nFmWsda3mTYUPYMZzWE4hMqpDgFPcJhw3prArMThDPbR3Hx7E6NRAAR0LqcrdtsbDqu2T0tto1rpnFILdvHL4PqEUfTmF2mkM+DKj7lKwvvZUbukqBwLrnnbdfyqZJryzGAMIa2JvMEMYszGsYyiPXZvYx6Luk54oWOlOrwEKrCY4NMPwch6DbFq6KpnNSQwOpgRYCz7wpjk57X+NGJmo85tYKc+TNa1rT4/DxG9v6SHkpXmmPeHhzIIW8MOdkFjxB5o6Qn8Fa0c6Tt6br2gzkrGr1eK5/+RiIgEzVhcRrqdY/p7PLmKXqawrEvIv9QZ3ijytPNwinlC8XdRLO/YvP33PjcI9WSMcHV6POP9KPMo1rngaIPMegKgAvTEouNFKp4v3wAXRXX5xEjwXAmM5wyB/SAOaPPCK/emls9kqolHsaj7nuTTbrvSV8bqzUwzQ"
	proofTest := "g53N8ecorvG2sDgNv8D7quVhKMIIpdP9Bqk/8gmV5cJ5Rhk9gKvb4F0ll8J/ZZJVqa27OyciJwx6lym6QpVK9q1ASrqio7rD5POMDGm64Iay/ixXXn+//F+uKgDXADj9AySri2J1j3qEkqqe3kxKthw94DzAfUBPncHfTPazVtE48AfzB1KWZA7Vf/x/3phYs4ckcP7ZrdVViJVLbUgFy543dpKfEH2MD30ZLLYRhw8SatRCyIJuTZcMlluEKG+d"
	inputsTest := "aZ8tqrOeEJKt4AMqiRF/WJhIKTDC0HeDTgiJVLZ8OEs="

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, vk, witness, err := decodeTestVector(vkTest, proofTest, inputsTest)
		if err != nil {
			b.Fatal(err)
		}
		if err = Verify(&proof, &vk, witness); err != nil {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkGroth16Verify15inputsBLS(b *testing.B) {
	vkTest := "tRpqHB4HADuHAUvHTcrzxmq1awdwEBA0GOJfebYTODyUqXBQ7FkYrz1oDvPyx5Z3sUmODSJXAQmAFBVnS2t+Xzf5ZCr1gCtMiJVjQ48/nob/SkrS4cTHHjbKIVS9cdD/BG/VDrZvBt/dPqXmdUFyFuTTMrViagR57YRrDmm1qm5LQ/A8VwUBdiArwgRQXH9jsYhgVmfcRAjJytrbYeR6ck4ZfmGr6x6akKiBLY4B1l9LaHTyz/6KSM5t8atpuR3HBJZfbBm2/K8nnYTl+mAU/EnIN3YQdUd65Hsd4Gtf6VT2qfz6hcrSgHutxR1usIL2kyU9X4Kqjx6I6zYwVbn7PWbiy3OtY277z4ggIqW6AuDgzUeIyG9a4stMeQ07mOV/Ef4faj+eh4GJRKjJm7aUTYJCSAGY6klOXNoEzB54XF4EY5pkMPfW73SmxJi9B0aHkZWDy2tzUlwvxZ/BfsDkUZnt6mI+qdDOtTG6JFItSQZotYGDBm6zPczwo3ZAGpr8gibTE6DjT7GGNDEl26jgAJ3aAdBrf7Yb0vWEYizOJK4SO/Ud+4/WxXDby7xbwlFYkgEtYbMO6PXozhRqDiotJ0CfdSExNHA9A37mR/bpNOKyhArfyvSBIJnUQgOw5wMBq+GOP5n78E99a5rY4FXGUmM3LGdp/CvkGITYf04SWHkZAEueYH96Ys5jrHlIZQA2k9j02Ji+SL82DJFH8LDh77fgh9zh0wAjCAqY7/r72434RDA97bfEZJavRmAENsgflsSVb8d9rQMBpWl3Xkb8mNlUOSf+LAXeXYQR42Z4yuUjwAUvk//+imuhsWF8ZCMkpb9wQ/6crVH4E5E3f6If/Mt/DcenWlPNtvu2CJFatc8q31aSdnWhMN8U65SX3DBouDc8EXDFd5twy4VWMS5lhY6VbU/lS8T8oyhr+NIpstsKUmSh0EM1rGyUh2PNgIYzoeBznHWagp2WO3nIbNYIcXEROBT8QpqA4Dqzxv665jwajGXmAawRvdZqzLqvCkeujekplZYoV0aXEnYEOIvfF7d4xay3qkx2NspooM4HeZpiHknIWkUVhGVJBzBDLjLBjiGBK+TGHfH8Oadexhdet7ExyIWibSmamWQvffZkyl3WnMoVbTQ3lOks4Mca3sU5hp1iMepdu0rKoBh0NXcw9F9hkiggDIkRNINq2rlvUypPiSmp8U8tDSMeG0YVSovFlA4DsjBwntJH45NgNbY/Rbu/hfe7QskTkBiTo2A+kmYSH75Uvf2UAXwBAT1PoE0sqtYndF2Kbthl6GylV3j9NIKtIzHd/GwleExuM7KlI1H22P78br5zmh8D7V1aFcxPpftQhjch4abXuxEP4ahgfNmthdhoSvQykLhjbmG9BrvwmyaDRd/sHCTeSXmLqIybrd6tA8ZLJq2DLzKJEOlmfM9aIihLe/FLndfnTSkNK2et4o8vM3YjAmgOnrAo7JIp"
	proofTest := "lgFU4Jyo9GdHL7w31u3zXc8RQRnHVarZWNfd0lD45GvvQtwrZ1Y1OKB4T29a79UagPHOdk1S0k0hYAYQyyNAfRUzde1HP8R+2dms75gGZEnx2tXexEN+BVjRJfC8PR1lFJa6xvsEx5uSrOZzKmoMfCwcA55SMT5jFo4+KyWg2wP5OnFPx7XTdEKvf5YhpY0krQKiq3OUu79EwjNF1xV1+iLxx2KEIyK7RSYxO1BHrKOGOEzxSUK00MA+YVHe+DvW"
	inputsTest := "aZ8tqrOeEJKt4AMqiRF/WJhIKTDC0HeDTgiJVLZ8OEtiLNj7hflFeVnNXPguxyoqkI/V7pGJtXBpH5N+RswQNA0b23aM33aH0HKHOWoGY/T/L7TQzYFGJ3vTLiXDFZg1OVqkGOMvqAgonOrHGi6IgcALyUMyCKlL5BQY23SeILJpYKolybJNwJfbjxpg0Oz+D2fr7r9XL1GMvgblu52bVQT1fR8uCRJfSsgA2OGw6k/MpKDCfMcjbR8jnZa8ROEvF4cohm7iV1788Vp2/2bdcEZRQSoaGV8pOmA9EkqzJVRABjkDso40fnQcm2IzjBUOsX+uFExVan56/vl9VZVwB0wnee3Uxiredn0kOayiPB16yimxXCDet+M+0UKjmIlmXYpkrCDrH0dn53w+U3OHqMQxPDnUpYBxadM1eI8xWFFxzaLkvega0q0DmEquyY02yiTqo+7Q4qaJVTLgu6/8ekzPxGKRi845NL8gRgaTtM3kidDzIQpyODZD0yeEZDY1M+3sUKHcVkhoxTQBTMyKJPc+M5DeBL3uaWMrvxuL6q8+X0xeBt+9kguPUNtIYqUgPAaXvM2i041bWHTJ0dZLyDJVOyzGaXRaF4mNkAuh4Et6Zw5PuOpMM2mI1oFKEZj7"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, vk, witness, err := decodeTestVector(vkTest, proofTest, inputsTest)
		if err != nil {
			b.Fatal(err)
		}
		if err = Verify(&proof, &vk, witness); err != nil {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkGroth16Verify16inputsBLS(b *testing.B) {
	vkTest := "kY4NWaOoYItWtLKVQnxDh+XTsa0Yev5Ae3Q9vlQSKp6+IUtwS7GH5ZrZefmBEwWEqvAtYaSs5qW3riOiiRFoLp7MThW4vCEhK0j8BZY5ZM/tnjB7mrLB59kGvzpW8PM/AoQRIWzyvO3Dxxfyj/UQcQRw+KakVRvrFca3Vy2K5cFwxYHwl6PFDM+OmGrlgOCoqZtY1SLOd+ovmFOODKiHBZzDZhC/lRfjKVy4LzI7AXDuFn4tlWoT7IsJyy6lYNaWFfLjYZPAsrv1gXJ1NYat5B6E0Pnz5C67u2Uigmlol2D91re3oAqIo+r8kiyFKOSBooG0cMN47zQor6qj0owuxJjn5Ymrcd/FCQ1ud4cKoUlNaGWIekSjxJEB87elMy5oEUlUzVI9ObMm+2SE3Udgws7pkMM8fgQUQUqUVyc7sNCE9m/hQzlwtbXrNSS5Pb+6ow7aHMOavjVyaXiS0f6b1pwJpS1yT+K85UA1CLqqxCaEw5+8WAjMzBOrKmxBUpYApI4FBAIa/SjeU/wYnljUUMTMfnBfCQ8MS01hFSQZSoPx1do8Zxn5Y3NPgpaomXDfpyVK9Q0U0NkqQqPsk+T+AroxQGxq9f/HOX5I5ZibF27dZ32tCbTKo22GgspqtAv2iv06PubySY5lRIEYlCjr5j8Ahl9gFvN+22cIh1iGiuwByhPjGDgP5h78xZXCBoJekEYPcI2C0LtBch5pZC/JpS1kF9lBLndodhIlutEr3mkKohR+D/czN/FTdxU2b82QqfZOHc+6rv2biEXy8AdoAMykj1dsIw7/d5M8XcgPiUzNko4H6p02Rt2R01MOYboTogaQH8lyU6o8c+iORRGEoZDTq4htC+Qa7AXTodvSmG33IrwJVGOKDMtvWI1VYdhWs32SB0W1d+BrFb0ObBGsz+Un7P+V8qerCMqu906BkbjdWmsKbKQBFC8/YDTdSi92rIq1ISUQWn88AgW/q+u6KPxybU5EZgbA+EZwCDB6MyBNhHcrAvVFeX+kj1RY1Gx1kzCE3ldsT37sCbayFtyMMbL6gDQCoTadJX/jhs9wgp0dZujwOk0Wefhgy1BUHXl/q+2nXAKPvKmli6Wo7/pYr/q13Gcsj7Z7WSKVn4Fm4XfkJD62q6paCxO51BlJQEcnpNPKS7+zjhmQlTRiEryD8ve7KQzk20eb4TgIMR1hI5pnQmjGeT56xZySp2nDnYDsqsnXB5uQY8lyf6IYC/PHzEb3rSx91k0ZEu5w5IMrVK8otNzZHrUuM0aPdImpLQJ4qEgvmezORpcUCq4SRp9bGl3/yzXE5tWZgn3Q6kXyjFMhu+foTYy1NV+HJbJI1nYMjeTr3f+RxSphIYWyMZ7sD3RgDzRk5iQqD1J+8rdOIZliObfrmWaro/BBxNvd1fPAlFEPiDegBcDaVWHS2A1FPIC9d+DU05vizrBfli6su9rCvSBNVnoDSBF2zeU+2NjXj7ycHYxCuZgl8dBu8FZjvjlDUZCqfdq3PszQeo2X55trDJEHeVWaRoIcgiG2hfTN"
	proofTest := "jqPSA/XKqZDJnRSmM0sJxbrFv7GUcA45QMysIx1xTsI3+2iysF5Tr68565ZuO65qjo2lklZpQo+wtyKSA/56EaKOJZCZhSvDdBEdvVYJCjmWusuK5qav7xZO0w5W1qRiEgIdcGUz5V7JHqfRf4xI6/uUD846alyzzNjxQtKErqJbRw6yyBO6j6box363pinjiMTzU4w/qltzFuOEpKxy/H3vyH8RcsF24Ou/Rb6vfR7cSLtLwCsf/BMtPcsQfdRK"
	inputsTest := "aZ8tqrOeEJKt4AMqiRF/WJhIKTDC0HeDTgiJVLZ8OEtiLNj7hflFeVnNXPguxyoqkI/V7pGJtXBpH5N+RswQNA0b23aM33aH0HKHOWoGY/T/L7TQzYFGJ3vTLiXDFZg1OVqkGOMvqAgonOrHGi6IgcALyUMyCKlL5BQY23SeILJpYKolybJNwJfbjxpg0Oz+D2fr7r9XL1GMvgblu52bVQT1fR8uCRJfSsgA2OGw6k/MpKDCfMcjbR8jnZa8ROEvF4cohm7iV1788Vp2/2bdcEZRQSoaGV8pOmA9EkqzJVRABjkDso40fnQcm2IzjBUOsX+uFExVan56/vl9VZVwB0wnee3Uxiredn0kOayiPB16yimxXCDet+M+0UKjmIlmXYpkrCDrH0dn53w+U3OHqMQxPDnUpYBxadM1eI8xWFFxzaLkvega0q0DmEquyY02yiTqo+7Q4qaJVTLgu6/8ekzPxGKRi845NL8gRgaTtM3kidDzIQpyODZD0yeEZDY1M+3sUKHcVkhoxTQBTMyKJPc+M5DeBL3uaWMrvxuL6q8+X0xeBt+9kguPUNtIYqUgPAaXvM2i041bWHTJ0dZLyDJVOyzGaXRaF4mNkAuh4Et6Zw5PuOpMM2mI1oFKEZj7Xqf/yAmy/Le3GfJnMg5vNgE7QxmVsjuKUP28iN8rdi4="

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, vk, witness, err := decodeTestVector(vkTest, proofTest, inputsTest)
		if err != nil {
			b.Fatal(err)
		}
		if err = Verify(&proof, &vk, witness); err != nil {
			b.Fatal("verification failed")
		}
	}
}

func (vk *VerifyingKey) FromBellmanVerifyingKey(bvk *BellmanVerifyingKey) {
	vk.e, _ = curve.Pair([]curve.G1Affine{bvk.G1.Alpha}, []curve.G2Affine{bvk.G2.Beta})
	vk.G2.gammaNeg.Neg(&bvk.G2.Gamma)
	vk.G2.deltaNeg.Neg(&bvk.G2.Delta)
	vk.G1.K = make([]curve.G1Affine, len(bvk.G1.Ic))
	copy(vk.G1.K, bvk.G1.Ic)
}

type BellmanVerifyingKey struct {
	G1 struct {
		Alpha/*, Beta, Delta*/ curve.G1Affine
		Ic []curve.G1Affine
	}
	G2 struct {
		Beta, Gamma, Delta curve.G2Affine
	}
}

func (vk *BellmanVerifyingKey) ReadFrom(r io.Reader) (n int64, err error) {

	// note: this is how bellman encodes the verifying key
	// however, our test vectors don't encode G1.Beta, G1.Delta and the length of ic

	// writer.write_all(self.alpha_g1.to_uncompressed().as_ref())?;
	// writer.write_all(self.beta_g1.to_uncompressed().as_ref())?;
	// writer.write_all(self.beta_g2.to_uncompressed().as_ref())?;
	// writer.write_all(self.gamma_g2.to_uncompressed().as_ref())?;
	// writer.write_all(self.delta_g1.to_uncompressed().as_ref())?;
	// writer.write_all(self.delta_g2.to_uncompressed().as_ref())?;
	// writer.write_u32::<BigEndian>(self.ic.len() as u32)?;
	// for ic in &self.ic {
	// 	writer.write_all(ic.to_uncompressed().as_ref())?;
	// }

	// first part, the points
	{
		dec := curve.NewDecoder(r)

		toDecode := []interface{}{
			&vk.G1.Alpha,
			// &vk.G1.Beta,
			&vk.G2.Beta,
			&vk.G2.Gamma,
			// &vk.G1.Delta,
			&vk.G2.Delta,
		}

		for _, v := range toDecode {
			if err := dec.Decode(v); err != nil {
				return dec.BytesRead(), err
			}
		}
		n += dec.BytesRead()
	}

	// the slice len is encoded slightly differently
	{
		// var buf [4]byte
		// var read int
		// read, err = io.ReadFull(r, buf[:])
		// n += int64(read)
		// if err != nil {
		// 	return
		// }
		// lPublicInputs := binary.BigEndian.Uint32(buf[:4])
		// vk.G1.Ic = make([]curve.G1Affine, lPublicInputs)
		dec := curve.NewDecoder(r)
		var p curve.G1Affine
		for {
			err := dec.Decode(&p)
			if err == io.EOF {
				break
			}
			if err != nil {
				return n + dec.BytesRead(), err
			}
			vk.G1.Ic = append(vk.G1.Ic, p)
		}
		n += dec.BytesRead()
	}

	return
}

func decodeInputs(b []byte) (r []fr.Element, err error) {
	const frSize = fr.Limbs * 8
	if (len(b) % frSize) != 0 {
		return nil, errors.New("invalid input size")
	}
	r = make([]fr.Element, 1+(len(b)/frSize))
	r[0].SetOne().FromMont()
	offset := 0
	for i := 1; i < len(r); i++ {
		r[i].SetBytes(b[offset : offset+frSize]).FromMont()
		// witness[strconv.Itoa(i+1)] = r[i]
		offset += frSize
	}

	return
}
