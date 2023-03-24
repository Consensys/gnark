package polynomial

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

// 4 variables
//
// sparse Eq:
// ~~~~~~~~~~
// 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1
// 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0
// 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0
// 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0
// 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0
// 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0
// 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0
// 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0
// 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0
// 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0
// 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0
// 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0
// 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0
// 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0
// 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0
// 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
//
// first fold:
// ~~~~~~~~~~~
// 0   0   0   0   0   0   0   1-r 0 0 0 0 0 0 0 r
// 0   0   0   0   0   0   1-r 0   0 0 0 0 0 0 r 0
// 0   0   0   0   0   1-r 0   0   0 0 0 0 0 r 0 0
// 0   0   0   0   1-r 0   0   0   0 0 0 0 r 0 0 0
// 0   0   0   1-r 0   0   0   0   0 0 0 r 0 0 0 0
// 0   0   1-r 0   0   0   0   0   0 0 r 0 0 0 0 0
// 0   1-r 0   0   0   0   0   0   0 r 0 0 0 0 0 0
// 1-r 0   0   0   0   0   0   0   r 0 0 0 0 0 0 0
//
// second fold:
// ~~~~~~~~~~~~
// 0          0          0          (1-r)(1-s) 0      0      0      (1-r)s 0      0      0      r(1-s) 0  0  0  rs
// 0          0          (1-r)(1-s) 0          0      0      (1-r)s 0      0      0      r(1-s) 0      0  0  rs 0
// 0          (1-r)(1-s) 0          0          0      (1-r)s 0      0      0      r(1-s) 0      0      0  rs 0  0
// (1-r)(1-s) 0          0          0          (1-r)s 0      0      0      r(1-s) 0      0      0      rs 0  0  0
//
// third fold:
// ~~~~~~~~~~~
// 0               (1-r)(1-s)(1-t) 0           (1-r)(1-s)t 0           (1-r)s(1-t) 0       (1-r)st 0           r(1-s)(1-t) 0      r(1-s)t 0       rs(1-t) 0   rst
// (1-r)(1-s)(1-t) 0               (1-r)(1-s)t             (1-r)s(1-t)             (1-r)st 0       r(1-s)(1-t)             r(1-s)t        rs(1-t) 0       rst 0
//
// fourth fold:
// ~~~~~~~~~~~~
// 0 :	(1-r) * (1-s) * (1-t) * (1-u),
// 1 :	(1-r) * (1-s) * (1-t) *   u  ,
// 2 :	(1-r) * (1-s) *   t   * (1-u),
// 3 :	(1-r) * (1-s) *   t   *   u  ,
// 4 :	(1-r) *   s   * (1-t) * (1-u),
// 5 :	(1-r) *   s   * (1-t) *   u  ,
// 6 :	(1-r) *   s   *   t   * (1-u),
// 7 :	(1-r) *   s   *   t   *   u  ,
// 8 :	  r   * (1-s) * (1-t) * (1-u),
// 9 :	  r   * (1-s) * (1-t) *   u  ,
// 10:	  r   * (1-s) *   t   * (1-u),
// 11:	  r   * (1-s) *   t   *   u  ,
// 12:	  r   *   s   * (1-t) * (1-u),
// 13:	  r   *   s   * (1-t) *   u  ,
// 14:	  r   *   s   *   t   * (1-u),
// 15:	  r   *   s   *   t   *   u  ,
//
// (array of length 16)

func correctFoldedEqTable(r, s, t, u fr.Element) BookKeepingTable {
	result := make([]fr.Element, 16)

	var one fr.Element
	one.SetOne()

	var R fr.Element // 1 - r
	var S fr.Element // 1 - s
	var T fr.Element // 1 - t
	var U fr.Element // 1 - u

	R.Sub(&one, &r)
	S.Sub(&one, &s)
	T.Sub(&one, &t)
	U.Sub(&one, &u)

	var RS fr.Element // (1-r) * (1-r)
	var Rs fr.Element // (1-r) *   s
	var rS fr.Element //   r   * (1-s)
	var rs fr.Element //   r   *   s
	var TU fr.Element // (1-t) * (1-u)
	var Tu fr.Element // (1-t) *   u
	var tU fr.Element //   t   * (1-u)
	var tu fr.Element //   t   *   u

	RS.Mul(&R, &S)
	Rs.Mul(&R, &s)
	rS.Mul(&r, &S)
	rs.Mul(&r, &s)
	TU.Mul(&T, &U)
	Tu.Mul(&T, &u)
	tU.Mul(&t, &U)
	tu.Mul(&t, &u)

	result[0].Mul(&RS, &TU)  // (1-r) (1-s) (1-t) (1-u),
	result[1].Mul(&RS, &Tu)  // (1-r) (1-s) (1-t)   u  ,
	result[2].Mul(&RS, &tU)  // (1-r) (1-s)   t   (1-u),
	result[3].Mul(&RS, &tu)  // (1-r) (1-s)   t     u  ,
	result[4].Mul(&Rs, &TU)  // (1-r)   s   (1-t) (1-u),
	result[5].Mul(&Rs, &Tu)  // (1-r)   s   (1-t)   u  ,
	result[6].Mul(&Rs, &tU)  // (1-r)   s     t   (1-u),
	result[7].Mul(&Rs, &tu)  // (1-r)   s     t     u  ,
	result[8].Mul(&rS, &TU)  //   r   (1-s) (1-t) (1-u),
	result[9].Mul(&rS, &Tu)  //   r   (1-s) (1-t)   u  ,
	result[10].Mul(&rS, &tU) //   r   (1-s)   t   (1-u),
	result[11].Mul(&rS, &tu) //   r   (1-s)   t     u  ,
	result[12].Mul(&rs, &TU) //   r     s   (1-t) (1-u),
	result[13].Mul(&rs, &Tu) //   r     s   (1-t)   u  ,
	result[14].Mul(&rs, &tU) //   r     s     t   (1-u),
	result[15].Mul(&rs, &tu) //   r     s     t     u  ,

	return NewBookKeepingTable(result)
}

func TestGetFoldedEqTable(t *testing.T) {

	var a, b, c, d fr.Element
	a.SetUint64(1789)
	b.SetUint64(4141)
	c.SetUint64(7654)
	d.SetUint64(1337)

	realResult := correctFoldedEqTable(a, b, c, d)

	// a.SetUint64(1776)
	qPrime := []fr.Element{a, b, c, d}

	computedResult := GetFoldedEqTable(qPrime)

	assert.Equal(
		t,
		realResult,
		computedResult,
		"Erroneous getFoldedEqTable result.",
	)
}
