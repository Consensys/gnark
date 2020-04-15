package template

const EddsaTest = `
import (
	"testing"

	"github.com/consensys/gurvy/{{toLower .Curve}}/fr"
	"github.com/consensys/gurvy/{{toLower .Curve}}/twistededwards"
)

func TestEddsa(t *testing.T) {

	edcurve := twistededwards.GetEdwardsCurve()

	var seed [32]byte
	s := []byte("eddsa")
	for i, v := range s {
		seed[i] = v
	}

	// create eddsa obj and sign a message
	signer := New(seed, edcurve)
	var msg fr.Element
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978")
	signature, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	// verifies correct msg
	res, err := Verify(signature, msg, signer.Pub, signer.curveParams)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verifiy correct signature should return true")
	}

	// verifies wrong msg
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035979")
	res, err = Verify(signature, msg, signer.Pub, signer.curveParams)
	if err != nil {
		t.Fatal(err)
	}
	if res {
		t.Fatal("Verfiy wrong signature should be false")
	}

}

`
