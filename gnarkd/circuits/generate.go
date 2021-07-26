package main

import (
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"

	cs_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	cs_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	cs_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	cs_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"
	cs_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/cs"

	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzg_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
)

//go:generate go run generate.go
func main() {
	var circuit cubic.Circuit

	var kCache kzgCache
	kCache.m = make(map[ecc.ID][]kzgInstance)

	for _, b := range backend.Implemented() {
		for _, curve := range ecc.Implemented() {
			circuitID := filepath.Join(b.String(), curve.String(), "cubic")
			os.MkdirAll(circuitID, 0700)

			log.Println("compiling", circuitID)
			ccs, err := frontend.Compile(curve, b, &circuit)
			if err != nil {
				log.Fatal(err)
			}
			writeGnarkObject(ccs, filepath.Join(circuitID, "cubic"+".ccs"))

			if b == backend.GROTH16 {
				log.Println("groth16 setup", circuitID)
				pk, vk, err := groth16.Setup(ccs)
				if err != nil {
					log.Fatal(err)
				}
				writeGnarkObject(pk, filepath.Join(circuitID, "cubic"+".pk"))
				writeGnarkObject(vk, filepath.Join(circuitID, "cubic"+".vk"))
			} else if b == backend.PLONK {
				log.Println("plonk setup", circuitID)
				kzg := kCache.getSRS(ccs)
				pk, _, err := plonk.Setup(ccs, kzg)
				if err != nil {
					log.Fatal(err)
				}
				writeGnarkObject(pk, filepath.Join(circuitID, "cubic"+".pk"))
				writeGnarkObject(kzg, filepath.Join(circuitID, "cubic"+".kzg"))
			}
		}
	}
}

func writeGnarkObject(o io.WriterTo, filePath string) {
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}
	_, err = o.WriteTo(file)
	file.Close()
	if err != nil {
		log.Fatal(err)
	}
}

// -------------------------------------------------------------------------------------------------
// TODO find a better home for this
// duplicate from backend/plonk/assert.go
// enables to create a (unsafe) KZG scheme without randomness.
// used for integration tests here.

type kzgCache struct {
	m map[ecc.ID][]kzgInstance
}

type kzgInstance struct {
	size uint64
	kzg  kzg.SRS
}

func (k *kzgCache) getSRS(ccs frontend.CompiledConstraintSystem) kzg.SRS {
	size := getKZGSize(ccs)
	instances, ok := k.m[ccs.CurveID()]
	if ok {
		// find an instance >= size
		for _, k := range instances {
			if k.size >= size {
				return k.kzg
			}
		}
	}

	// we need to do a new KZG
	fakeRandomness := new(big.Int).SetInt64(42)

	var toReturn kzg.SRS
	var err error
	switch ccs.CurveID() {
	case ecc.BN254:
		toReturn, err = kzg_bn254.NewSRS(size, fakeRandomness)
	case ecc.BLS12_381:
		toReturn, err = kzg_bls12381.NewSRS(size, fakeRandomness)
	case ecc.BLS12_377:
		toReturn, err = kzg_bls12377.NewSRS(size, fakeRandomness)
	case ecc.BW6_761:
		toReturn, err = kzg_bw6761.NewSRS(size, fakeRandomness)
	case ecc.BLS24_315:
		toReturn, err = kzg_bls24315.NewSRS(size, fakeRandomness)
	default:
		panic("unknown constraint system type")
	}
	if err != nil {
		panic(err)
	}
	instances = append(instances, kzgInstance{size: size, kzg: toReturn})
	k.m[ccs.CurveID()] = instances
	return toReturn
}

func getKZGSize(ccs frontend.CompiledConstraintSystem) uint64 {
	var s uint64
	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		s = uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
	case *cs_bls12381.SparseR1CS:
		s = uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
	case *cs_bls12377.SparseR1CS:
		s = uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
	case *cs_bw6761.SparseR1CS:
		s = uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
	case *cs_bls24315.SparseR1CS:
		s = uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
	default:
		panic("unknown constraint system type")
	}
	return ecc.NextPowerOfTwo(s) + 3
}
