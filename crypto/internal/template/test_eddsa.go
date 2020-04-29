package template

const EddsaTest = `

import (
	"testing"

	"github.com/consensys/gnark/crypto/hash/mimc/{{toLower .Curve}}"
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

	hFunc := {{toLower .Curve}}.NewMiMC("seed")

	// create eddsa obj and sign a message
	signer, pubKey, privKey := New(seed, edcurve, hFunc)
	var msg fr.Element
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978")
	signature, err := Sign(signer, msg, pubKey, privKey)
	if err != nil {
		t.Fatal(err)
	}

	// verifies correct msg
	res, err := Verify(signer, signature, msg, pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verifiy correct signature should return true")
	}

	// verifies wrong msg
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035979")
	res, err = Verify(signer, signature, msg, pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if res {
		t.Fatal("Verfiy wrong signature should be false")
	}

}

`
