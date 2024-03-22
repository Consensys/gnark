package fflonk

import "io"

// ExportSolidity exports the verifying key to a solidity smart contract.
//
// See https://github.com/ConsenSys/gnark-tests for example usage.
//
// Code has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability.
func (vk *VerifyingKey) ExportSolidity(w io.Writer) error {
	// funcMap := template.FuncMap{
	// 	"hex": func(i int) string {
	// 		return fmt.Sprintf("0x%x", i)
	// 	},
	// 	"mul": func(a, b int) int {
	// 		return a * b
	// 	},
	// 	"inc": func(i int) int {
	// 		return i + 1
	// 	},
	// 	"frstr": func(x fr.Element) string {
	// 		// we use big.Int to always get a positive string.
	// 		// not the most efficient hack, but it works better for .sol generation.
	// 		bv := new(big.Int)
	// 		x.BigInt(bv)
	// 		return bv.String()
	// 	},
	// 	"fpstr": func(x fp.Element) string {
	// 		bv := new(big.Int)
	// 		x.BigInt(bv)
	// 		return bv.String()
	// 	},
	// 	"add": func(i, j int) int {
	// 		return i + j
	// 	},
	// }

	// t, err := template.New("t").Funcs(funcMap).Parse(tmplSolidityVerifier)
	// if err != nil {
	// 	return err
	// }
	// return t.Execute(w, vk)
	return nil
}
