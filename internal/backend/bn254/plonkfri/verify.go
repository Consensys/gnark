package plonkfri

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fri"
	"github.com/consensys/gnark/internal/backend/bn254/witness"
)

var ErrInvalidAlgebraicRelation = errors.New("algebraic relation does not hold")

func VerifyFri(proof *Proof, vk *VerifyingKey, publicWitness witness.Witness) error {

	// 1 - verify that the commitments are low degree polynomials

	// ql, qr, qm, qo, qkIncomplete
	err := vk.Iopp.VerifyProofOfProximity(vk.Qpp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(vk.Qpp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(vk.Qpp[2])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(vk.Qpp[3])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(vk.Qpp[4])
	if err != nil {
		return err
	}

	// l, r, o
	err = vk.Iopp.VerifyProofOfProximity(proof.LROpp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(proof.LROpp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(proof.LROpp[2])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(proof.Zpp)
	if err != nil {
		return err
	}

	// h0, h1, h2
	err = vk.Iopp.VerifyProofOfProximity(proof.Hpp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(proof.Hpp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(proof.Hpp[2])
	if err != nil {
		return err
	}

	// s1, s2, s3
	err = vk.Iopp.VerifyProofOfProximity(vk.Spp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(vk.Spp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(vk.Spp[2])
	if err != nil {
		return err
	}

	// id1, id2, id3
	err = vk.Iopp.VerifyProofOfProximity(vk.Idpp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(vk.Idpp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyProofOfProximity(vk.Idpp[2])
	if err != nil {
		return err
	}

	// Z
	err = vk.Iopp.VerifyProofOfProximity(proof.Zpp)
	if err != nil {
		return err
	}

	// 2 - verify the openings

	// ql, qr, qm, qo, qkIncomplete
	openingPosition := uint64(1)
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsQlQrQmQoQkincompletemp[0], vk.Qpp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsQlQrQmQoQkincompletemp[1], vk.Qpp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsQlQrQmQoQkincompletemp[2], vk.Qpp[2])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsQlQrQmQoQkincompletemp[3], vk.Qpp[3])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsQlQrQmQoQkincompletemp[4], vk.Qpp[4])
	if err != nil {
		return err
	}

	// l, r, o
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsLROmp[0], proof.LROpp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsLROmp[1], proof.LROpp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsLROmp[2], proof.LROpp[2])
	if err != nil {
		return err
	}

	// h0, h1, h2
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsHmp[0], proof.Hpp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsHmp[1], proof.Hpp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsHmp[2], proof.Hpp[2])
	if err != nil {
		return err
	}

	// s0, s1, s2
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsS1S2S3mp[0], vk.Spp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsS1S2S3mp[1], vk.Spp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsS1S2S3mp[2], vk.Spp[2])
	if err != nil {
		return err
	}

	// id0, id1, id2
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsId1Id2Id3mp[0], vk.Idpp[0])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsId1Id2Id3mp[1], vk.Idpp[1])
	if err != nil {
		return err
	}
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsId1Id2Id3mp[2], vk.Idpp[2])
	if err != nil {
		return err
	}

	// Z, Zshift
	err = vk.Iopp.VerifyOpening(openingPosition, proof.OpeningsZmp[0], proof.Zpp)
	if err != nil {
		return err
	}

	rho := uint64(fri.GetRho())
	// We multiply by 2 because FRI is instantiated with pk.Domain[0].Cardinality+2, which makes
	// the iop's domain of size rho*(2*pk.Domain[0].Cardinality).
	friSize := 2 * rho * vk.Size
	shiftedOpeningPosition := (openingPosition + uint64(2*rho)) % friSize
	err = vk.Iopp.VerifyOpening(shiftedOpeningPosition, proof.OpeningsZmp[1], proof.Zpp)
	if err != nil {
		return err
	}

	// verification of the algebraic relation
	var ql, qr, qm, qo, qk fr.Element
	ql.Set(&proof.OpeningsQlQrQmQoQkincompletemp[0].ClaimedValue)
	qr.Set(&proof.OpeningsQlQrQmQoQkincompletemp[1].ClaimedValue)
	qm.Set(&proof.OpeningsQlQrQmQoQkincompletemp[2].ClaimedValue)
	qo.Set(&proof.OpeningsQlQrQmQoQkincompletemp[3].ClaimedValue)
	qk.Set(&proof.OpeningsQlQrQmQoQkincompletemp[4].ClaimedValue) // -> to be completed

	// fmt.Printf("ql(zeta): %s\n", ql.String())
	// fmt.Printf("qr(zeta): %s\n", qr.String())
	// fmt.Printf("qm(zeta): %s\n", qm.String())
	// fmt.Printf("qo(zeta): %s\n", qo.String())
	// fmt.Printf("qk(zeta): %s\n", qk.String())

	var l, r, o fr.Element
	l.Set(&proof.OpeningsLROmp[0].ClaimedValue)
	r.Set(&proof.OpeningsLROmp[1].ClaimedValue)
	o.Set(&proof.OpeningsLROmp[2].ClaimedValue)
	// fmt.Printf("l(zeta): %s\n", l.String())
	// fmt.Printf("r(zeta): %s\n", r.String())
	// fmt.Printf("o(zeta): %s\n", o.String())

	var h1, h2, h3 fr.Element
	h1.Set(&proof.OpeningsHmp[0].ClaimedValue)
	h2.Set(&proof.OpeningsHmp[1].ClaimedValue)
	h3.Set(&proof.OpeningsHmp[2].ClaimedValue)
	// fmt.Printf("h1(zeta): %s\n", h1.String())
	// fmt.Printf("h2(zeta): %s\n", h2.String())
	// fmt.Printf("h3(zeta): %s\n", h3.String())

	var s1, s2, s3 fr.Element
	s1.Set(&proof.OpeningsS1S2S3mp[0].ClaimedValue)
	s2.Set(&proof.OpeningsS1S2S3mp[1].ClaimedValue)
	s3.Set(&proof.OpeningsS1S2S3mp[2].ClaimedValue)
	// fmt.Printf("s1(zeta): %s\n", proof.OpeningsS1S2S3mp[0].ClaimedValue.String())
	// fmt.Printf("s2(zeta): %s\n", proof.OpeningsS1S2S3mp[1].ClaimedValue.String())
	// fmt.Printf("s3(zeta): %s\n", proof.OpeningsS1S2S3mp[2].ClaimedValue.String())

	var id1, id2, id3 fr.Element
	id1.Set(&proof.OpeningsId1Id2Id3mp[0].ClaimedValue)
	id2.Set(&proof.OpeningsId1Id2Id3mp[1].ClaimedValue)
	id3.Set(&proof.OpeningsId1Id2Id3mp[2].ClaimedValue)
	// fmt.Printf("id1(zeta): %s\n", proof.OpeningsId1Id2Id3mp[0].ClaimedValue.String())
	// fmt.Printf("id2(zeta): %s\n", proof.OpeningsId1Id2Id3mp[1].ClaimedValue.String())
	// fmt.Printf("id3(zeta): %s\n", proof.OpeningsId1Id2Id3mp[2].ClaimedValue.String())

	var z, zshift fr.Element
	z.Set(&proof.OpeningsZmp[0].ClaimedValue)
	zshift.Set(&proof.OpeningsZmp[1].ClaimedValue)
	fmt.Printf("z(zeta): %s\n", z.String())
	fmt.Printf("z(u*zeta): %s\n", zshift.String())

	// 2 - compute the LHS: (ql*l+..+qk)+ α*(z(μx)*(l+β*s₁+γ)*..-z*(l+β*id1+γ))+α²*z*(l1-1)
	var alpha, beta, gamma fr.Element
	beta.SetUint64(9)
	gamma.SetUint64(10)
	alpha.SetUint64(11)

	// point of evaluation
	var zeta, zetaShifted fr.Element
	zeta.Exp(vk.GenOpening, big.NewInt(int64(openingPosition)))
	zetaShifted.Mul(&zeta, &vk.Generator)

	var lhs, t1, t2, t3, tmp, tmp2 fr.Element
	// 2.1 (ql*l+..+qk)
	t1.Mul(&l, &ql)
	tmp.Mul(&r, &qr)
	t1.Add(&t1, &tmp)
	tmp.Mul(&qm, &l).Mul(&tmp, &r)
	t1.Add(&t1, &tmp)
	tmp.Mul(&o, &qo)
	t1.Add(&tmp, &t1)
	tmp = completeQk(publicWitness, vk, zeta)
	tmp.Add(&qk, &tmp)
	t1.Add(&tmp, &t1)

	// 2.2 (z(ux)*(l+β*s1+γ)*..-z*(l+β*id1+γ))
	t2.Mul(&beta, &s1).Add(&t2, &l).Add(&t2, &gamma)
	tmp.Mul(&beta, &s2).Add(&tmp, &r).Add(&tmp, &gamma)
	t2.Mul(&tmp, &t2)
	tmp.Mul(&beta, &s3).Add(&tmp, &o).Add(&tmp, &gamma)
	t2.Mul(&tmp, &t2).Mul(&t2, &zshift)

	tmp.Mul(&beta, &id1).Add(&tmp, &l).Add(&tmp, &gamma)
	tmp2.Mul(&beta, &id2).Add(&tmp2, &r).Add(&tmp2, &gamma)
	tmp.Mul(&tmp, &tmp2)
	tmp2.Mul(&beta, &id3).Add(&tmp2, &o).Add(&tmp2, &gamma)
	tmp.Mul(&tmp2, &tmp).Mul(&tmp, &z)

	t2.Sub(&t2, &tmp)

	// 2.3 (z-1)*l1
	var one fr.Element
	one.SetOne()
	t3.Exp(zeta, big.NewInt(int64(vk.Size))).Sub(&t3, &one)
	tmp.Sub(&zeta, &one).Inverse(&tmp).Mul(&tmp, &vk.SizeInv)
	t3.Mul(&tmp, &t3)
	tmp.Sub(&z, &one)
	t3.Mul(&tmp, &t3)

	// 2.4 (ql*l+s+qk) + α*(z(ux)*(l+β*s1+γ)*...-z*(l+β*id1+γ)..)+ α²*z*(l1-1)
	lhs.Set(&t3).Mul(&lhs, &alpha).Add(&lhs, &t2).Mul(&lhs, &alpha).Add(&lhs, &t1)

	// 3 - compute the RHS
	var rhs fr.Element
	tmp.Exp(zeta, big.NewInt(int64(vk.Size+2)))
	rhs.Mul(&h3, &tmp).
		Add(&rhs, &h2).
		Mul(&rhs, &tmp).
		Add(&rhs, &h1)

	tmp.Exp(zeta, big.NewInt(int64(vk.Size))).Sub(&tmp, &one)
	rhs.Mul(&rhs, &tmp)

	// 4 - verify the relation LHS==RHS
	if !rhs.Equal(&lhs) {
		return ErrInvalidAlgebraicRelation
	}

	return nil

}

func Verify(proof *Proof, vk *VerifyingKey, publicWitness witness.Witness) error {

	// 0 - derive the point of evaluation
	var zeta fr.Element
	zeta.SetString("10359452186428527605436343203440067497552205259388878191021578220384701716497")

	// 1 - verify all the openings
	vk.Cscheme.Verify(vk.Ql, proof.OpeningsQlQrQmQoQkincomplete[0], zeta)
	vk.Cscheme.Verify(vk.Qr, proof.OpeningsQlQrQmQoQkincomplete[1], zeta)
	vk.Cscheme.Verify(vk.Qm, proof.OpeningsQlQrQmQoQkincomplete[2], zeta)
	vk.Cscheme.Verify(vk.Qo, proof.OpeningsQlQrQmQoQkincomplete[3], zeta)
	vk.Cscheme.Verify(vk.QkIncomplete, proof.OpeningsQlQrQmQoQkincomplete[4], zeta)

	// fmt.Printf("ql(zeta): %s\n", proof.OpeningsQlQrQmQoQkincomplete[0].Val.String())
	// fmt.Printf("qr(zeta): %s\n", proof.OpeningsQlQrQmQoQkincomplete[1].Val.String())
	// fmt.Printf("qm(zeta): %s\n", proof.OpeningsQlQrQmQoQkincomplete[2].Val.String())
	// fmt.Printf("qo(zeta): %s\n", proof.OpeningsQlQrQmQoQkincomplete[3].Val.String())
	// fmt.Printf("qk(zeta): %s\n", proof.OpeningsQlQrQmQoQkincomplete[4].Val.String())

	vk.Cscheme.Verify(proof.LRO[0], proof.OpeningsLRO[0], zeta)
	vk.Cscheme.Verify(proof.LRO[1], proof.OpeningsLRO[1], zeta)
	vk.Cscheme.Verify(proof.LRO[2], proof.OpeningsLRO[2], zeta)
	// fmt.Printf("l(zeta): %s\n", proof.OpeningsLRO[0].Val.String())
	// fmt.Printf("r(zeta): %s\n", proof.OpeningsLRO[1].Val.String())
	// fmt.Printf("o(zeta): %s\n", proof.OpeningsLRO[2].Val.String())

	vk.Cscheme.Verify(proof.H[0], proof.OpeningsH[0], zeta)
	vk.Cscheme.Verify(proof.H[1], proof.OpeningsH[1], zeta)
	vk.Cscheme.Verify(proof.H[2], proof.OpeningsH[1], zeta)
	// fmt.Printf("h1(zeta): %s\n", proof.OpeningsH[0].Val.String())
	// fmt.Printf("h2(zeta): %s\n", proof.OpeningsH[1].Val.String())
	// fmt.Printf("h3(zeta): %s\n", proof.OpeningsH[2].Val.String())

	vk.Cscheme.Verify(vk.S[0], proof.OpeningsS1S2S3[0], zeta)
	vk.Cscheme.Verify(vk.S[1], proof.OpeningsS1S2S3[1], zeta)
	vk.Cscheme.Verify(vk.S[2], proof.OpeningsS1S2S3[2], zeta)
	// fmt.Printf("s1(zeta): %s\n", proof.OpeningsS1S2S3[0].Val.String())
	// fmt.Printf("s2(zeta): %s\n", proof.OpeningsS1S2S3[1].Val.String())
	// fmt.Printf("s3(zeta): %s\n", proof.OpeningsS1S2S3[2].Val.String())

	vk.Cscheme.Verify(vk.Id[0], proof.OpeningsId1Id2Id3[0], zeta)
	vk.Cscheme.Verify(vk.Id[1], proof.OpeningsId1Id2Id3[1], zeta)
	vk.Cscheme.Verify(vk.Id[2], proof.OpeningsId1Id2Id3[2], zeta)
	// fmt.Printf("id1(zeta): %s\n", proof.OpeningsId1Id2Id3[0].Val.String())
	// fmt.Printf("id2(zeta): %s\n", proof.OpeningsId1Id2Id3[1].Val.String())
	// fmt.Printf("id3(zeta): %s\n", proof.OpeningsId1Id2Id3[2].Val.String())

	vk.Cscheme.Verify(proof.Z, proof.OpeningsZ[0], zeta)
	var zetaShifted fr.Element
	zetaShifted.Mul(&vk.Generator, &zeta)
	vk.Cscheme.Verify(proof.Z, proof.OpeningsZ[1], zetaShifted)
	fmt.Printf("z(zeta): %s\n", proof.OpeningsZ[0].Val.String())
	fmt.Printf("z(u*zeta): %s\n", proof.OpeningsZ[1].Val.String())

	// 2 - compute the LHS: (ql*l+..+qk)+ α*(z(μx)*(l+β*s₁+γ)*..-z*(l+β*id1+γ))+α²*z*(l1-1)
	var alpha, beta, gamma fr.Element
	beta.SetUint64(9)
	gamma.SetUint64(10)
	alpha.SetUint64(11)

	var lhs, t1, t2, t3, tmp, tmp2 fr.Element
	// 2.1 (ql*l+..+qk)
	t1.Mul(&proof.OpeningsLRO[0].Val, &proof.OpeningsQlQrQmQoQkincomplete[0].Val)
	tmp.Mul(&proof.OpeningsLRO[1].Val, &proof.OpeningsQlQrQmQoQkincomplete[1].Val)
	t1.Add(&t1, &tmp)
	tmp.Mul(&proof.OpeningsQlQrQmQoQkincomplete[2].Val, &proof.OpeningsLRO[0].Val).
		Mul(&tmp, &proof.OpeningsLRO[1].Val)
	t1.Add(&t1, &tmp)
	tmp.Mul(&proof.OpeningsLRO[2].Val, &proof.OpeningsQlQrQmQoQkincomplete[3].Val)
	t1.Add(&tmp, &t1)
	tmp = completeQk(publicWitness, vk, zeta)
	tmp.Add(&proof.OpeningsQlQrQmQoQkincomplete[4].Val, &tmp)
	t1.Add(&tmp, &t1)

	// 2.2 (z(ux)*(l+β*s1+γ)*..-z*(l+β*id1+γ))
	t2.Mul(&beta, &proof.OpeningsS1S2S3[0].Val).Add(&t2, &proof.OpeningsLRO[0].Val).Add(&t2, &gamma)
	tmp.Mul(&beta, &proof.OpeningsS1S2S3[1].Val).Add(&tmp, &proof.OpeningsLRO[1].Val).Add(&tmp, &gamma)
	t2.Mul(&tmp, &t2)
	tmp.Mul(&beta, &proof.OpeningsS1S2S3[2].Val).Add(&tmp, &proof.OpeningsLRO[2].Val).Add(&tmp, &gamma)
	t2.Mul(&tmp, &t2).Mul(&t2, &proof.OpeningsZ[1].Val)

	tmp.Mul(&beta, &proof.OpeningsId1Id2Id3[0].Val).Add(&tmp, &proof.OpeningsLRO[0].Val).Add(&tmp, &gamma)
	tmp2.Mul(&beta, &proof.OpeningsId1Id2Id3[1].Val).Add(&tmp2, &proof.OpeningsLRO[1].Val).Add(&tmp2, &gamma)
	tmp.Mul(&tmp, &tmp2)
	tmp2.Mul(&beta, &proof.OpeningsId1Id2Id3[2].Val).Add(&tmp2, &proof.OpeningsLRO[2].Val).Add(&tmp2, &gamma)
	tmp.Mul(&tmp2, &tmp).Mul(&tmp, &proof.OpeningsZ[0].Val)

	t2.Sub(&t2, &tmp)

	// 2.3 (z-1)*l1
	var one fr.Element
	one.SetOne()
	t3.Exp(zeta, big.NewInt(int64(vk.Size))).Sub(&t3, &one)
	tmp.Sub(&zeta, &one).Inverse(&tmp).Mul(&tmp, &vk.SizeInv)
	t3.Mul(&tmp, &t3)
	tmp.Sub(&proof.OpeningsZ[0].Val, &one)
	t3.Mul(&tmp, &t3)

	// 2.4 (ql*l+s+qk) + α*(z(ux)*(l+β*s1+γ)*...-z*(l+β*id1+γ)..)+ α²*z*(l1-1)
	lhs.Set(&t3).Mul(&lhs, &alpha).Add(&lhs, &t2).Mul(&lhs, &alpha).Add(&lhs, &t1)

	// 3 - compute the RHS
	var rhs fr.Element
	tmp.Exp(zeta, big.NewInt(int64(vk.Size+2)))
	rhs.Mul(&proof.OpeningsH[2].Val, &tmp).
		Add(&rhs, &proof.OpeningsH[1].Val).
		Mul(&rhs, &tmp).
		Add(&rhs, &proof.OpeningsH[0].Val)

	tmp.Exp(zeta, big.NewInt(int64(vk.Size))).Sub(&tmp, &one)
	rhs.Mul(&rhs, &tmp)

	// 4 - verify the relation LHS==RHS
	if !rhs.Equal(&lhs) {
		return errors.New("invalid relation")
	}

	return nil

}

// completeQk returns ∑_{i<nb_public_inputs}w_i*L_i
func completeQk(publicWitness witness.Witness, vk *VerifyingKey, zeta fr.Element) fr.Element {

	var res fr.Element

	// use L_i+1 = w*Li*(X-z**i)/(X-z**i+1)
	var l, tmp, acc, one fr.Element
	one.SetOne()
	acc.SetOne()
	l.Sub(&zeta, &one).Inverse(&l).Mul(&l, &vk.SizeInv)
	tmp.Exp(zeta, big.NewInt(int64(vk.Size))).Sub(&tmp, &one)
	l.Mul(&l, &tmp)

	for i := 0; i < len(publicWitness); i++ {

		tmp.Mul(&l, &publicWitness[i])
		res.Add(&res, &tmp)

		tmp.Sub(&zeta, &acc)
		l.Mul(&l, &tmp).Mul(&l, &vk.Generator)
		acc.Mul(&acc, &vk.Generator)
		tmp.Sub(&zeta, &acc)
		l.Div(&l, &tmp)
	}

	return res
}
