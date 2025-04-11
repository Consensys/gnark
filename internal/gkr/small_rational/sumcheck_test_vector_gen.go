package gkr

import (
	"encoding/json"
	"fmt"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/internal/small_rational"
	"github.com/consensys/gnark/internal/small_rational/polynomial"
	"hash"
	"math/bits"
	"os"
	"path/filepath"
	"runtime/pprof"
)

func runMultilin(testCaseInfo *sumcheckTestCaseInfo) error {

	var poly polynomial.MultiLin
	if v, err := sliceToElementSlice(testCaseInfo.Values); err == nil {
		poly = v
	} else {
		return err
	}

	var (
		hsh hash.Hash
		err error
	)

	if hsh, err = hashFromDescription(testCaseInfo.Hash); err != nil {
		return err
	}

	proof, err := sumcheckProve(
		&singleMultilinClaim{poly}, fiatshamir.WithHash(hsh))
	if err != nil {
		return err
	}
	testCaseInfo.Proof = sumcheckToPrintableProof(proof)

	// Verification
	if v, _err := sliceToElementSlice(testCaseInfo.Values); _err == nil {
		poly = v
	} else {
		return _err
	}
	var claimedSum small_rational.SmallRational
	if _, err = claimedSum.SetInterface(testCaseInfo.ClaimedSum); err != nil {
		return err
	}

	if err = sumcheckVerify(singleMultilinLazyClaim{g: poly, claimedSum: claimedSum}, proof, fiatshamir.WithHash(hsh)); err != nil {
		return fmt.Errorf("proof rejected: %v", err)
	}

	proof.partialSumPolys[0][0].Add(&proof.partialSumPolys[0][0], toElement(1))
	if err = sumcheckVerify(singleMultilinLazyClaim{g: poly, claimedSum: claimedSum}, proof, fiatshamir.WithHash(hsh)); err == nil {
		return fmt.Errorf("bad proof accepted")
	}

	pprof.StopCPUProfile()
	//return f.Close()

	return nil
}

func runSumcheck(testCaseInfo *sumcheckTestCaseInfo) error {
	switch testCaseInfo.Type {
	case "multilin":
		return runMultilin(testCaseInfo)
	default:
		return fmt.Errorf("type \"%s\" unrecognized", testCaseInfo.Type)
	}
}

func GenerateSumcheckVectors() error {
	// read the test vectors file, generate the proof, make sure it verifies,
	// and add the proof to the same file
	const relPath = "../../gkr/test_vectors/sumcheck/vectors.json"

	var filename string
	var err error
	if filename, err = filepath.Abs(relPath); err != nil {
		return err
	}

	var bytes []byte

	if bytes, err = os.ReadFile(filename); err != nil {
		return err
	}

	var testCasesInfo sumcheckTestCasesInfo
	if err = json.Unmarshal(bytes, &testCasesInfo); err != nil {
		return err
	}

	failed := false
	for name, testCase := range testCasesInfo {
		if err = runSumcheck(testCase); err != nil {
			fmt.Println(name, ":", err)
			failed = true
		}
	}

	if failed {
		return fmt.Errorf("test case failed")
	}

	if bytes, err = json.MarshalIndent(testCasesInfo, "", "\t"); err != nil {
		return err
	}

	return os.WriteFile(filename, bytes, 0)
}

type sumcheckTestCasesInfo map[string]*sumcheckTestCaseInfo

type sumcheckTestCaseInfo struct {
	Type        string                 `json:"type"`
	Hash        hashDescription        `json:"hash"`
	Values      []interface{}          `json:"values"`
	Description string                 `json:"description"`
	Proof       SumcheckPrintableProof `json:"proof"`
	ClaimedSum  interface{}            `json:"claimedSum"`
}

type SumcheckPrintableProof struct {
	PartialSumPolys [][]interface{} `json:"partialSumPolys"`
	FinalEvalProof  interface{}     `json:"finalEvalProof"`
}

func sumcheckToPrintableProof(proof sumcheckProof) (printable SumcheckPrintableProof) {
	if proof.finalEvalProof != nil {
		panic("null expected")
	}
	printable.FinalEvalProof = struct{}{}
	printable.PartialSumPolys = elementSliceSliceToInterfaceSliceSlice(proof.partialSumPolys)
	return
}

type singleMultilinClaim struct {
	g polynomial.MultiLin
}

func (c singleMultilinClaim) proveFinalEval([]small_rational.SmallRational) []small_rational.SmallRational {
	return nil // verifier can compute the final eval itself
}

func (c singleMultilinClaim) varsNum() int {
	return bits.TrailingZeros(uint(len(c.g)))
}

func (c singleMultilinClaim) claimsNum() int {
	return 1
}

func sumForX1One(g polynomial.MultiLin) polynomial.Polynomial {
	sum := g[len(g)/2]
	for i := len(g)/2 + 1; i < len(g); i++ {
		sum.Add(&sum, &g[i])
	}
	return []small_rational.SmallRational{sum}
}

func (c singleMultilinClaim) combine(small_rational.SmallRational) polynomial.Polynomial {
	return sumForX1One(c.g)
}

func (c *singleMultilinClaim) next(r small_rational.SmallRational) polynomial.Polynomial {
	c.g.Fold(r)
	return sumForX1One(c.g)
}

type singleMultilinLazyClaim struct {
	g          polynomial.MultiLin
	claimedSum small_rational.SmallRational
}

func (c singleMultilinLazyClaim) verifyFinalEval(r []small_rational.SmallRational, _ small_rational.SmallRational, purportedValue small_rational.SmallRational, _ []small_rational.SmallRational) error {
	val := c.g.Evaluate(r, nil)
	if val.Equal(&purportedValue) {
		return nil
	}
	return fmt.Errorf("mismatch")
}

func (c singleMultilinLazyClaim) combinedSum(small_rational.SmallRational) small_rational.SmallRational {
	return c.claimedSum
}

func (c singleMultilinLazyClaim) degree(int) int {
	return 1
}

func (c singleMultilinLazyClaim) claimsNum() int {
	return 1
}

func (c singleMultilinLazyClaim) varsNum() int {
	return bits.TrailingZeros(uint(len(c.g)))
}
