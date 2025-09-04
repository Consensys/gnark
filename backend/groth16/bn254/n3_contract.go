package groth16

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const n3ContractTemplate = `
{{- $numPublic := sub (len .Vk.G1.K) 1 }}
{{- $numCommitments := len .Vk.PublicAndCommitmentCommitted }}
{{- $numWitness := sub $numPublic $numCommitments }}
{{- $PublicAndCommitmentCommitted := .Vk.PublicAndCommitmentCommitted }}
using Neo.SmartContract.Framework.Attributes;
using System;
using System.ComponentModel;
using System.Numerics;
using Neo.SmartContract.Framework;

namespace Neo.Compiler.CSharp.TestContracts	
{
    [DisplayName("ZkpVerifyContract")]
    public class ZkpVerifyContract : SmartContract.Framework.SmartContract
    {
        static readonly string PublicInputNotInField = "PublicInputNotInField";
        static readonly string ProofInvalid = "ProofInvalid";
        static readonly string CommitmentInvalid = "CommitmentInvalid";

        static readonly BigInteger PRECOMPILE_MODEXP = 0x05;
        static readonly BigInteger PRECOMPILE_ADD = 0x06;
        static readonly BigInteger PRECOMPILE_MUL = 0x07;
        static readonly BigInteger PRECOMPILE_VERIFY = 0x08;

 		// Base field Fp order P and scalar field Fr order R.
        // For BN254 these are computed as follows:
        //     t = 4965661367192848881
        //     P = 36⋅t⁴ + 36⋅t³ + 24⋅t² + 6⋅t + 1
        //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
        static readonly BigInteger P =  BigInteger.Parse("21888242871839275222246405745257275088696311157297823662689037894645226208583");//0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
        static readonly BigInteger R = BigInteger.Parse("21888242871839275222246405745257275088548364400416034343698204186575808495617");//0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

		// Extension field Fp2 = Fp[i] / (i² + 1)
        // Note: This is the complex extension field of Fp with i² = -1.
        //       Values in Fp2 are represented as a pair of Fp elements (a₀, a₁) as a₀ + a₁⋅i.
        // Note: The order of Fp2 elements is *opposite* that of the pairing contract, which
        //       expects Fp2 elements in order (a₁, a₀). This is also the order in which
        //       Fp2 elements are encoded in the public interface as this became convention.

        // Constants in Fp
        static readonly BigInteger FRACTION_1_2_FP = BigInteger.Parse("10944121435919637611123202872628637544348155578648911831344518947322613104292");//0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4
        static readonly BigInteger FRACTION_27_82_FP = BigInteger.Parse("19485874751759354771024239261021720505790618469301721065564631296452457478373");//0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5
        static readonly BigInteger FRACTION_3_82_FP = BigInteger.Parse("21621313080719284060999498358119991246151234191964923374119659383734918571893");//0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775

        // Exponents for inversions and square roots mod P
        static readonly BigInteger EXP_INVERSE_FP = BigInteger.Parse("21888242871839275222246405745257275088696311157297823662689037894645226208581"); // P - 2//0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45
        static readonly BigInteger EXP_SQRT_FP = BigInteger.Parse("5472060717959818805561601436314318772174077789324455915672259473661306552146"); // (P + 1) / 4;//0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52

      	// Automatically filled and generated
		
		// Groth16 alpha point in G1
        static readonly BigInteger ALPHA_X = BigInteger.Parse("{{ (fpstr .Vk.G1.Alpha.X) }}");
        static readonly BigInteger ALPHA_Y = BigInteger.Parse("{{ (fpstr .Vk.G1.Alpha.Y) }} ");

		// Groth16 alpha point in G2 in powers of i 
        static readonly BigInteger BETA_NEG_X_0 = BigInteger.Parse("{{ (fpstr .Vk.G2.Beta.X.A0) }}");
        static readonly BigInteger BETA_NEG_X_1 = BigInteger.Parse("{{ (fpstr .Vk.G2.Beta.X.A1) }}");
        static readonly BigInteger BETA_NEG_Y_0 = BigInteger.Parse("{{ (fpstr .Vk.G2.Beta.Y.A0) }}");
        static readonly BigInteger BETA_NEG_Y_1 = BigInteger.Parse("{{ (fpstr .Vk.G2.Beta.Y.A1) }}");

    	// Groth16 gamma point in G2 in powers of i
        static readonly BigInteger GAMMA_NEG_X_0 = BigInteger.Parse("{{ (fpstr .Vk.G2.Gamma.X.A0) }}");
        static readonly BigInteger GAMMA_NEG_X_1 = BigInteger.Parse("{{ (fpstr .Vk.G2.Gamma.X.A1) }}");
        static readonly BigInteger GAMMA_NEG_Y_0 = BigInteger.Parse("{{ (fpstr .Vk.G2.Gamma.Y.A0) }}");
        static readonly BigInteger GAMMA_NEG_Y_1 = BigInteger.Parse("{{ (fpstr .Vk.G2.Gamma.Y.A1) }}");

    	// Groth16 delta point in G2 in powers of i
        static readonly BigInteger DELTA_NEG_X_0 = BigInteger.Parse("{{ (fpstr .Vk.G2.Delta.X.A0) }}");
        static readonly BigInteger DELTA_NEG_X_1 = BigInteger.Parse("{{ (fpstr .Vk.G2.Delta.X.A1) }}");
        static readonly BigInteger DELTA_NEG_Y_0 = BigInteger.Parse("{{ (fpstr .Vk.G2.Delta.Y.A0) }}");
        static readonly BigInteger DELTA_NEG_Y_1 = BigInteger.Parse("{{ (fpstr .Vk.G2.Delta.Y.A1) }}");

        {{- if gt $numCommitments 0 }}
    	// Pedersen G point in G2 in powers of i
    	{{- $cmtVk0 := index .Vk.CommitmentKeys 0 }}
        static readonly BigInteger PEDERSEN_G_X_0 = BigInteger.Parse("{{ (fpstr $cmtVk0.G.X.A0) }}");
        static readonly BigInteger PEDERSEN_G_X_1 = BigInteger.Parse("{{ (fpstr $cmtVk0.G.X.A1) }}");
        static readonly BigInteger PEDERSEN_G_Y_0 = BigInteger.Parse("{{ (fpstr $cmtVk0.G.Y.A0) }}");
        static readonly BigInteger PEDERSEN_G_Y_1 = BigInteger.Parse("{{ (fpstr $cmtVk0.G.Y.A1) }}");

    	// Pedersen GSigmaNeg point in G2 in powers of i
        static readonly BigInteger PEDERSEN_GSIGMANEG_X_0 = BigInteger.Parse("{{ (fpstr $cmtVk0.GSigmaNeg.X.A0) }}");
        static readonly BigInteger PEDERSEN_GSIGMANEG_X_1 = BigInteger.Parse("{{ (fpstr $cmtVk0.GSigmaNeg.X.A1) }}");
        static readonly BigInteger PEDERSEN_GSIGMANEG_Y_0 = BigInteger.Parse("{{ (fpstr $cmtVk0.GSigmaNeg.Y.A0) }}");
        static readonly BigInteger PEDERSEN_GSIGMANEG_Y_1 = BigInteger.Parse("{{ (fpstr $cmtVk0.GSigmaNeg.Y.A1) }}");
        {{ end }}

        // Constant and public input points
    	{{- $k0 := index .Vk.G1.K 0}}
        static readonly BigInteger CONSTANT_X = BigInteger.Parse("{{ (fpstr $k0.X) }}");
        static readonly BigInteger CONSTANT_Y = BigInteger.Parse("{{ (fpstr $k0.Y) }}");

        {{- range $i, $ki := .Vk.G1.K }}
        	{{- if gt $i 0 }}
        static readonly BigInteger PUB_{{sub $i 1}}_X = BigInteger.Parse("{{ (fpstr $ki.X) }}");
        static readonly BigInteger PUB_{{sub $i 1}}_Y = BigInteger.Parse("{{ (fpstr $ki.Y) }}");
            {{- end }}
    	{{- end }}

        /// Negation in Fp.
        /// @notice Returns a number x such that a + x = 0 in Fp.
        /// @notice The input does not need to be reduced.
        /// @param a the base
        /// @return x the result
        [Safe]
        public static BigInteger Negate(BigInteger a)
        {
            unchecked
            {
                return (P - (a % P)) % P;
            }
        }

        /// Exponentiation in Fp.
        /// @notice Returns a number x such that a ^ e = x in Fp.
        /// @notice The input does not need to be reduced.
        /// @param a the base
        /// @param e the exponent
        /// @return x the result
        [Safe]
        public static BigInteger Exp(BigInteger a, BigInteger e)
        {
            return BigInteger.ModPow(a, e, P);
        }

        /// Exponentiation in Fp.
        /// @notice Returns a number x such that a*b = x in Fp.
        /// @notice The input does not need to be reduced.
        /// @param a the mul number 1
        /// @param b the mul number 2
        /// @return x the result
        [Safe]
        public static BigInteger MulMod(BigInteger a, BigInteger b, BigInteger p)
        {
            return a.ModMultiply(b, p);
        }

        /// Exponentiation in Fp.
        /// @notice Returns a number x such that a*b = x in Fp.
        /// @notice The input does not need to be reduced.
        /// @param a the add number 1
        /// @param b the add number 2
        /// @return x the result
        [Safe]
        public static BigInteger AddMod(BigInteger a, BigInteger b, BigInteger p)
        {
            return (a + b) % p;
        }

        /// Invertsion in Fp.
        /// @notice Returns a number x such that a * x = 1 in Fp.
        /// @notice The input does not need to be reduced.
        /// @notice Reverts with ProofInvalid() if the inverse does not exist
        /// @param a the input
        /// @return x the solution
        [Safe]
        public static BigInteger Invert_Fp(BigInteger a)
        {
            BigInteger x = Exp(a, EXP_INVERSE_FP);
            if (!MulMod(a, x, P).Equals(1))
            {
                throw new Exception(ProofInvalid);
            }
            return x;
        }

        /// Square root in Fp.
        /// @notice Returns a number x such that x * x = a in Fp.
        /// @notice Will revert with InvalidProof() if the input is not a square
        /// or not reduced.
        /// @param a the square
        /// @return x the solution
        [Safe]
        public static BigInteger Sqrt_Fp(BigInteger a)
        {
            BigInteger x = Exp(a, EXP_SQRT_FP);
            if (MulMod(x, x, P) != a)
            {
                throw new Exception(ProofInvalid);
            }
            return x;
        }

        /// Square test in Fp.
        /// @notice Returns whether a number x exists such that x * x = a in Fp.
        /// @notice Will revert with InvalidProof() if the input is not a square
        /// or not reduced.
        /// @param a the square
        /// @return x the solution
        [Safe]
        public static bool IsSquare_Fp(BigInteger a)
        {
            BigInteger x = Exp(a, EXP_SQRT_FP);
            return MulMod(x, x, P) == a;
        }

        /// Square root in Fp2.
        /// @notice Fp2 is the complex extension Fp[i]/(i^2 + 1). The input is
        /// a0 + a1 ⋅ i and the result is x0 + x1 ⋅ i.
        /// @notice Will revert with InvalidProof() if
        ///   * the input is not a square,
        ///   * the hint is incorrect, or
        ///   * the input coefficients are not reduced.
        /// @param a0 The real part of the input.
        /// @param a1 The imaginary part of the input.
        /// @param hint A hint which of two possible signs to pick in the equation.
        /// @return x0 The real part of the square root.
        /// @return x1 The imaginary part of the square root.
        [Safe]
        public static (BigInteger x0, BigInteger x1) Sqrt_Fp2(BigInteger a0, BigInteger a1, bool hint)
        {
            BigInteger d = Sqrt_Fp(AddMod(MulMod(a0, a0, P), MulMod(a1, a1, P), P));
            if (hint) d = Negate(d);

            BigInteger x0 = Sqrt_Fp(MulMod(AddMod(a0, d, P), FRACTION_1_2_FP, P));
            BigInteger x1 = MulMod(a1, Invert_Fp(MulMod(x0, 2, P)), P);

            // 结果校验
            if (a0 != AddMod(MulMod(x0, x0, P), Negate(MulMod(x1, x1, P)), P)
                || a1 != MulMod(2, MulMod(x0, x1, P), P))
            {
                throw new Exception(ProofInvalid);
            }
            return (x0, x1);
        }

        /// Compress a G1 point.
        /// @notice Reverts with InvalidProof if the coordinates are not reduced
        /// or if the point is not on the curve.
        /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
        /// @param x The X coordinate in Fp.
        /// @param y The Y coordinate in Fp.
        /// @return c The compresed point (x with one signal bit).
        [Safe]
        public static BigInteger Compress_g1(BigInteger x, BigInteger y)
        {
            if (x >= P || y >= P) throw new Exception(ProofInvalid);
            if (x == 0 && y == 0) return 0;

            BigInteger y_pos = Sqrt_Fp(AddMod(MulMod(MulMod(x, x, P), x, P), 3, P));
            if (y == y_pos) return (x << 1) | 0;
            if (y == Negate(y_pos)) return (x << 1) | 1;

            throw new Exception(ProofInvalid);
        }

        /// Decompress a G1 point.
        /// @notice Reverts with InvalidProof if the input does not represent a valid point.
        /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
        /// @param c The compresed point (x with one signal bit).
        /// @return x The X coordinate in Fp.
        /// @return y The Y coordinate in Fp.
        [Safe]
        public static (BigInteger x, BigInteger y) Decompress_g1(BigInteger c)
        {
            if (c == 0) return (0, 0);

            bool negatePoint = (c & 1) == 1;
            BigInteger x = c >> 1;
            if (x >= P) throw new Exception(ProofInvalid);

            BigInteger y = Sqrt_Fp(AddMod(MulMod(MulMod(x, x, P), x, P), 3, P));
            if (negatePoint) y = Negate(y);

            return (x, y);
        }

       /// Compress a G2 point.
        /// @notice Reverts with InvalidProof if the coefficients are not reduced
        /// or if the point is not on the curve.
        /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
        /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
        /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
        /// @param x0 The real part of the X coordinate.
        /// @param x1 The imaginary poart of the X coordinate.
        /// @param y0 The real part of the Y coordinate.
        /// @param y1 The imaginary part of the Y coordinate.
        /// @return c0 The first half of the compresed point (x0 with two signal bits).
        /// @return c1 The second half of the compressed point (x1 unmodified).
		[Safe]
        public static (BigInteger c0,BigInteger c1) Compress_g2(BigInteger x0, BigInteger x1, BigInteger y0, BigInteger y1)
        {
            if (x0 >= P || x1 >= P || y0 >= P || y1 >= P)
            {
                // G2 point not in field.
                throw new Exception(ProofInvalid);
            }
            if ((x0 | x1 | y0 | y1) == 0)
            {
                // Point at infinity
                return (0, 0);
            }

            // Compute y^2
            // Note: shadowing variables and scoping to avoid stack-to-deep.
            BigInteger y0_pos;
            BigInteger y1_pos;
            {
                BigInteger n3ab = MulMod(MulMod(x0, x1, P), P - 3, P);
                BigInteger a_3 = MulMod(MulMod(x0, x0, P), x0, P);
                BigInteger b_3 = MulMod(MulMod(x1, x1, P), x1, P);
                y0_pos = AddMod(FRACTION_27_82_FP, AddMod(a_3, MulMod(n3ab, x1, P), P), P);
                y1_pos = Negate(AddMod(FRACTION_3_82_FP, AddMod(b_3, MulMod(n3ab, x0, P), P), P));
            }

            // Determine hint bit
            // If this sqrt fails the x coordinate is not on the curve.
            bool hint;
            {
                BigInteger d = Sqrt_Fp(AddMod(MulMod(y0_pos, y0_pos, P), MulMod(y1_pos, y1_pos, P), P));
                hint = !IsSquare_Fp(MulMod(AddMod(y0_pos, d, P), FRACTION_1_2_FP, P));
            }
            BigInteger c0 = 0;
            BigInteger c1 = 0;
            // Recover y
            (y0_pos,y1_pos)= Sqrt_Fp2(y0_pos, y1_pos, hint);
            if (y0 == y0_pos && y1 == y1_pos)
            {
                c0 = (x0 << 2) | (hint ? 2 : 0) | 0;
                c1 = x1;
                return (c0, c1);
            }
            else if (y0 == Negate(y0_pos) && y1 == Negate(y1_pos))
            {
                c0 = (x0 << 2) | (hint ? 2 : 0) | 1;
                c1 = x1;
                return (c0, c1);
            }
            else
            {
                // G1 point not on curve.
                throw new Exception(ProofInvalid);
            }
        }

        /// Decompress a G2 point.
        /// @notice Reverts with InvalidProof if the input does not represent a valid point.
        /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
        /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
        /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
        /// @param c0 The first half of the compresed point (x0 with two signal bits).
        /// @param c1 The second half of the compressed point (x1 unmodified).
        /// @return x0 The real part of the X coordinate.
        /// @return x1 The imaginary poart of the X coordinate.
        /// @return y0 The real part of the Y coordinate.
        /// @return y1 The imaginary part of the Y coordinate.
        [Safe]
        public static (BigInteger x0, BigInteger x1, BigInteger y0, BigInteger y1)  Decompress_g2(BigInteger c0, BigInteger c1)
        {
            // Note that X = (0, 0) is not on the curve since 0³ + 3/(9 + i) is not a square.
            // so we can use it to represent the point at infinity.
            if (c0 == 0 && c1 == 0)
            {
                // Point at infinity as encoded in EIP197.
                return (0, 0, 0, 0);
            }
            bool negate_point = (c0 & 1) == 1;
            bool hint = (c0 & 2) == 2;
            BigInteger x0 = c0 >> 2;
            BigInteger x1 = c1;
            if (x0 >= P || x1 >= P)
            {
                // G2 x0 or x1 coefficient not in field.
                throw new Exception(ProofInvalid);
            }

            BigInteger n3ab = MulMod(MulMod(x0, x1, P), P - 3, P);
            BigInteger a_3 = MulMod(MulMod(x0, x0, P), x0, P);
            BigInteger b_3 = MulMod(MulMod(x1, x1, P), x1, P);

            BigInteger y0 = AddMod(FRACTION_27_82_FP, AddMod(a_3, MulMod(n3ab, x1, P), P), P);
            BigInteger y1 = Negate(AddMod(FRACTION_3_82_FP, AddMod(b_3, MulMod(n3ab, x0, P), P), P));

            // Note: sqrt_Fp2 reverts if there is no solution, i.e. the point is not on the curve.
            // Note: (X³ + 3/(9 + i)) is irreducible in Fp2, so y can not be zero.
            //       But y0 or y1 may still independently be zero.
            (y0,y1)= Sqrt_Fp2(y0, y1, hint);
            if (negate_point)
            {
                y0 = Negate(y0);
                y1 = Negate(y1);
            }
            return (x0,  x1, y0, y1);
        }
    }
}
`

// MarshalN3Contract converts a proof to a byte array that can be used in a
// n3 contract.
func (proof *Proof) MarshalN3Contract() []byte {
	var buf bytes.Buffer
	_, err := proof.WriteRawTo(&buf)
	if err != nil {
		panic(err)
	}

	// If there are no commitments, we can return only Ar | Bs | Krs
	if len(proof.Commitments) > 0 {
		return buf.Bytes()
	} else {
		return buf.Bytes()[:8*fr.Bytes]
	}
}
