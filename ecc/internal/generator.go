package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/consensys/gnark/ecc/internal/gpoint"
	"github.com/consensys/gnark/ecc/internal/tower"
	"github.com/consensys/gnark/ecc/internal/tower/fp12"
	"github.com/consensys/gnark/ecc/internal/tower/fp2"
	"github.com/consensys/gnark/ecc/internal/tower/fp6"

	"github.com/consensys/goff/cmd"
)

const fp2Name = "e2"
const fp6Name = "e6"
const fp12Name = "e12"

// input arguments, flags
var (
	fOutputDir   string
	fPackageName string
	ft           string
	ftNeg        bool
	fFp          string
	fFr          string
	fFp2         string
	fFp6         string
	// fFp12           string
	fMakeTestPoints bool
)

func init() {

	flag.StringVar(&fOutputDir, "out", "", "")
	flag.StringVar(&fPackageName, "package", "", "bls381, bls377, bn256")
	flag.StringVar(&ft, "t", "", "BLS12 family parameter, dictates p, r")
	flag.BoolVar(&ftNeg, "tNeg", false, "is t negative?")
	flag.StringVar(&fFp, "p", "", "prime base field")
	flag.StringVar(&fFr, "r", "", "prime subgroup order")
	flag.StringVar(&fFp2, "fp2", "", "a quadratic non-residue in fp.Element")
	flag.StringVar(&fFp6, "fp6", "", "a cubic non-residue in fp2")
	// flag.StringVar(&fFp12, "fp12", "", "a quadratic non-residue in fp6")
	flag.BoolVar(&fMakeTestPoints, "testpoints", false, "use sage to generate test points?")
}

type codegenData struct {
	path    string
	sources []string
}

func main() {
	flag.Parse()

	// uncomment for debugging
	// fOutputDir = "../bls377"
	// fPackageName = "bls377"
	// fFp = "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177"
	// fFr = "8444461749428370424248824938781546531375899335154063827935233455917409239041"
	// fFp2 = "5"
	// fFp6 = "0,1"
	// // fFp12 = "0,0,1,0,0,0"
	// fMakeTestPoints = true

	if fOutputDir == "" || fPackageName == "" || fFp == "" || fFr == "" || fFp2 == "" || fFp6 == "" || ft == "" {
		fmt.Fprintln(os.Stderr, "error: please specify -out, -package, -t, -fp, -fr, -fp2, -fp6")
		os.Exit(-1)
	}

	fFp6Split := strings.Split(fFp6, ",")
	if len(fFp6Split) != 2 {
		fmt.Fprintln(os.Stderr, "error: can't parse -fp6 as x,y")
		os.Exit(-1)
	}

	//----------------//
	// use goff to generate fp, fr
	//----------------//
	if err := cmd.GenerateFF("fp", "Element", fFp, filepath.Join(fOutputDir, "fp"), false); err != nil {
		fmt.Fprintln(os.Stderr, "goff field generation failed")
		os.Exit(-1)
	}
	if err := cmd.GenerateFF("fr", "Element", fFr, filepath.Join(fOutputDir, "fr"), false); err != nil {
		fmt.Fprintln(os.Stderr, "goff field generation failed")
		os.Exit(-1)
	}

	//----------------//
	// generate fp2
	//----------------//

	// TODO repeated code: refactor templateData across fp2, fp6, fp12

	{ // begin a block to avoid accidental reuse of fp2TemplateData, fp2Data
		fp2TemplateData := struct {
			PackageName   string
			Name          string
			Fp2NonResidue string
			TestPoints    []tower.TestPoint
			Methods       []tower.Method
			MethodTypes   tower.MethodTypeMap
		}{
			PackageName:   fPackageName,
			Name:          fp2Name,
			Fp2NonResidue: fFp2,
			Methods:       fp2.Methods[:],
			MethodTypes:   tower.MethodTypes,
		}

		var fp2Data []codegenData

		// source
		fp2Data = append(fp2Data, codegenData{
			path:    filepath.Join(fOutputDir, strings.ToLower(fp2TemplateData.Name)+".go"),
			sources: fp2.CodeSource,
		})

		// tests
		fp2Data = append(fp2Data, codegenData{
			path:    filepath.Join(fOutputDir, strings.ToLower(fp2TemplateData.Name)+"_test.go"),
			sources: fp2.CodeTest,
		})

		// test points
		if fMakeTestPoints {

			testInputs := fp2.GenerateTestInputs(fFp)
			var err error
			fp2TemplateData.TestPoints, err = tower.GenerateTestOutputs(testInputs, "../internal/tower/fp2/testpoints.sage", fFp, fFp2)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(-1)
			}
			if !sanityCheck(fp2TemplateData.TestPoints, fp2.Degree) {
				fmt.Fprintln(os.Stderr, "idiot!", err)
				os.Exit(-1)
			}

			fp2Data = append(fp2Data, codegenData{
				path:    filepath.Join(fOutputDir, strings.ToLower(fp2TemplateData.Name)+"testpoints_test.go"),
				sources: fp2.CodeTestPoints,
			})
		}

		if err := generateCode(fp2Data, fp2TemplateData); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(-1)
		}
	}

	//----------------//
	// generate fp6
	//----------------//
	{ // begin a block to avoid accidental reuse of fp6TemplateData, fp6Data
		fp6TemplateData := struct {
			PackageName   string
			Name          string
			Fp2Name       string
			Fp2NonResidue string
			Fp6NonResidue string
			TestPoints    []tower.TestPoint
			Methods       []tower.Method
			MethodTypes   tower.MethodTypeMap
		}{
			PackageName:   fPackageName,
			Name:          fp6Name,
			Fp2Name:       fp2Name,
			Fp6NonResidue: fFp6,
			Fp2NonResidue: fFp2,
			Methods:       fp6.Methods[:],
			MethodTypes:   tower.MethodTypes,
		}

		var fp6Data []codegenData

		// source
		fp6Data = append(fp6Data, codegenData{
			path:    filepath.Join(fOutputDir, strings.ToLower(fp6TemplateData.Name)+".go"),
			sources: fp6.CodeSource,
		})

		// tests
		fp6Data = append(fp6Data, codegenData{
			path:    filepath.Join(fOutputDir, strings.ToLower(fp6TemplateData.Name)+"_test.go"),
			sources: fp6.CodeTest,
		})

		// test points
		if fMakeTestPoints {

			testInputs := fp6.GenerateTestInputs(fFp)
			var err error
			fp6TemplateData.TestPoints, err = tower.GenerateTestOutputs(testInputs, "../internal/tower/fp6/testpoints.sage", fFp, fFp2, fFp6Split[0], fFp6Split[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(-1)
			}
			if !sanityCheck(fp6TemplateData.TestPoints, fp6.Degree) {
				fmt.Fprintln(os.Stderr, "idiot!", err)
				os.Exit(-1)
			}

			fp6Data = append(fp6Data, codegenData{
				path:    filepath.Join(fOutputDir, strings.ToLower(fp6TemplateData.Name)+"testpoints_test.go"),
				sources: fp6.CodeTestPoints,
			})
		}

		if err := generateCode(fp6Data, fp6TemplateData); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(-1)
		}
	}

	//----------------//
	// generate fp12
	//----------------//
	{ // begin a block to avoid accidental reuse of fp12TemplateData, fp12Data
		fp12TemplateData := struct {
			PackageName   string
			Name          string
			T             string
			TNeg          bool
			Fp            string
			Fp2Name       string
			Fp6Name       string
			Fp2NonResidue string
			Fp6NonResidue string
			TestPoints    []tower.TestPoint
			Methods       []tower.Method
			MethodTypes   tower.MethodTypeMap
		}{
			PackageName:   fPackageName,
			Name:          fp12Name,
			T:             ft,
			TNeg:          ftNeg,
			Fp:            fFp,
			Fp2Name:       fp2Name,
			Fp6Name:       fp6Name,
			Fp2NonResidue: fFp2,
			Fp6NonResidue: fFp6,
			Methods:       fp12.Methods[:],
			MethodTypes:   tower.MethodTypes,
		}

		var fp12Data []codegenData

		// source
		fp12Data = append(fp12Data, codegenData{
			path:    filepath.Join(fOutputDir, strings.ToLower(fp12TemplateData.Name)+".go"),
			sources: fp12.CodeSource,
		})

		// tests
		fp12Data = append(fp12Data, codegenData{
			path:    filepath.Join(fOutputDir, strings.ToLower(fp12TemplateData.Name)+"_test.go"),
			sources: fp12.CodeTest,
		})

		// test points
		if fMakeTestPoints {
			testInputs := fp12.GenerateTestInputs(fFp)

			sageArgs := []string{ft, fFp, fFr, fFp2}
			sageArgs = append(sageArgs, fFp6Split...)

			var err error
			fp12TemplateData.TestPoints, err = tower.GenerateTestOutputs(testInputs, "../internal/tower/fp12/testpoints.sage", sageArgs...)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(-1)
			}
			if !sanityCheck(fp12TemplateData.TestPoints, fp12.Degree) {
				fmt.Fprintln(os.Stderr, "idiot!", err)
				os.Exit(-1)
			}

			fp12Data = append(fp12Data, codegenData{
				path:    filepath.Join(fOutputDir, strings.ToLower(fp12TemplateData.Name)+"testpoints_test.go"),
				sources: fp12.CodeTestPoints,
			})
		}

		if err := generateCode(fp12Data, fp12TemplateData); err != nil {
			fmt.Println("error:", err)
			os.Exit(-1)
		}
	}

	//----------------//
	// generate gpoint
	//----------------//
	gpoints := []struct {
		structName string // G1, G2
		coordType  string
	}{
		{
			structName: "G1",
			coordType:  "fp.Element",
		},
		{
			structName: "G2",
			coordType:  fp2Name,
		},
	}

	for _, g := range gpoints {
		gpointTemplateData := struct {
			PackageName string
			Name        string
			CType       string
		}{
			PackageName: fPackageName,
			Name:        strings.ToUpper(g.structName),
			CType:       g.coordType,
		}

		var gpointData []codegenData

		// source
		gpointData = append(gpointData, codegenData{
			path:    filepath.Join(fOutputDir, strings.ToLower(gpointTemplateData.Name)+".go"),
			sources: gpoint.Src,
		})

		// tests
		gpointData = append(gpointData, codegenData{
			path:    filepath.Join(fOutputDir, strings.ToLower(gpointTemplateData.Name)+"_test.go"),
			sources: gpoint.Tst,
		})

		if err := generateCode(gpointData, gpointTemplateData); err != nil {
			fmt.Println("error:", err)
			os.Exit(-1)
		}
	}

	//----------------//
	// generate pairing
	//----------------//
	{ // begin a block to avoid accidental reuse of pairingTemplateData, pairingData
		pairingTemplateData := struct {
			PackageName string
			// Name          string
			T    string
			TNeg bool
			// Fp            string
			Fp2Name  string
			Fp6Name  string
			Fp12Name string
			// Fp2NonResidue string
			// Fp6NonResidue string
			// TestPoints    []tower.TestPoint
			// Methods       []tower.Method
			// MethodTypes   tower.MethodTypeMap
		}{
			PackageName: fPackageName,
			// Name:          fp12Name,
			T:    ft,
			TNeg: ftNeg,
			// Fp:            fFp,
			Fp2Name:  fp2Name,
			Fp6Name:  fp6Name,
			Fp12Name: fp12Name,
			// Fp2NonResidue: fFp2,
			// Fp6NonResidue: fFp6,
			// Methods:       fp12.Methods[:],
			// MethodTypes:   tower.MethodTypes,
		}

		var pairingData []codegenData

		// source
		// pairingData = append(pairingData, codegenData{
		// 	path:    filepath.Join(fOutputDir, "pairing.go"),
		// 	sources: pairing.CodeSource,
		// })

		// tests
		// pairingData = append(pairingData, codegenData{
		// 	path:    filepath.Join(fOutputDir, "pairing_test.go"),
		// 	sources: pairing.CodeTest,
		// })

		// test points
		// if fMakeTestPoints {
		// 	testInputs := fp12.GenerateTestInputs(fFp)

		// 	sageArgs := []string{ft, fFp, fFp2}
		// 	sageArgs = append(sageArgs, fFp6Split...)

		// 	var err error
		// 	pairingTemplateData.TestPoints, err = tower.GenerateTestOutputs(testInputs, "../internal/tower/fp12/testpoints.sage", sageArgs...)
		// 	if err != nil {
		// 		fmt.Fprintln(os.Stderr, "error:", err)
		// 		os.Exit(-1)
		// 	}
		// 	if !sanityCheck(pairingTemplateData.TestPoints, fp12.Degree) {
		// 		fmt.Fprintln(os.Stderr, "idiot!", err)
		// 		os.Exit(-1)
		// 	}

		// 	pairingData = append(pairingData, codegenData{
		// 		path:    filepath.Join(fOutputDir, strings.ToLower(pairingTemplateData.Name)+"testpoints_test.go"),
		// 		sources: fp12.CodeTestPoints,
		// 	})
		// }

		if err := generateCode(pairingData, pairingTemplateData); err != nil {
			fmt.Println("error:", err)
			os.Exit(-1)
		}
	}
}

func generateCode(data []codegenData, templateData interface{}) error {

	for _, d := range data {

		// create output file
		file, err := os.Create(d.path)
		if err != nil {
			return err
		}

		fmt.Printf("generating %-50s\n", d.path)

		// parse templates
		tmpl := template.Must(template.New("").
			Funcs(helpers()).
			Parse(aggregate(d.sources)))

		// execute template
		if err := tmpl.Execute(file, templateData); err != nil {
			file.Close()
			return err
		}
		file.Close()

		// run goformat to prettify output source
		if err := exec.Command("gofmt", "-s", "-w", d.path).Run(); err != nil {
			return err
		}
		if err := exec.Command("goimports", "-w", d.path).Run(); err != nil {
			return err
		}
	}
	return nil
}

func helpers() template.FuncMap {
	// functions used in template
	return template.FuncMap{
		"toLower":    strings.ToLower,
		"toUpper":    strings.ToUpper,
		"capitalize": strings.Title,
		"dict":       dict,
	}
}

func aggregate(values []string) string {
	var sb strings.Builder
	for _, v := range values {
		sb.WriteString(v)
	}
	return sb.String()
}

// TODO copied from goff. is this necessary??
func dict(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, errors.New("invalid dict call")
	}
	dict := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, errors.New("dict keys must be strings")
		}
		dict[key] = values[i+1]
	}
	return dict, nil
}

func sanityCheck(points []tower.TestPoint, degree int) bool {
	sane := true
	for i := range points {
		for j := range points[i].In {
			if len(points[i].In[j]) != degree {
				sane = false
			}
		}
		for j := range points[i].Out {
			if len(points[i].Out[j]) != degree {
				sane = false
			}
		}
	}
	return sane
}
