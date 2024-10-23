package fields_bw6761

import (
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		divE6Hint,
		inverseE6Hint,
		divE6By362880Hint,
		finalExpHint,
	}
}

func inverseE6Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bw6761.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[2])
			a.B0.A2.SetBigInt(inputs[4])
			a.B1.A0.SetBigInt(inputs[1])
			a.B1.A1.SetBigInt(inputs[3])
			a.B1.A2.SetBigInt(inputs[5])

			c.Inverse(&a)

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[2])
			c.B0.A2.BigInt(outputs[4])
			c.B1.A0.BigInt(outputs[1])
			c.B1.A1.BigInt(outputs[3])
			c.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func divE6Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, b, c bw6761.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[2])
			a.B0.A2.SetBigInt(inputs[4])
			a.B1.A0.SetBigInt(inputs[1])
			a.B1.A1.SetBigInt(inputs[3])
			a.B1.A2.SetBigInt(inputs[5])
			b.B0.A0.SetBigInt(inputs[6])
			b.B0.A1.SetBigInt(inputs[8])
			b.B0.A2.SetBigInt(inputs[10])
			b.B1.A0.SetBigInt(inputs[7])
			b.B1.A1.SetBigInt(inputs[9])
			b.B1.A2.SetBigInt(inputs[11])

			c.Inverse(&b).Mul(&c, &a)

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[2])
			c.B0.A2.BigInt(outputs[4])
			c.B1.A0.BigInt(outputs[1])
			c.B1.A1.BigInt(outputs[3])
			c.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func divE6By362880Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bw6761.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[2])
			a.B0.A2.SetBigInt(inputs[4])
			a.B1.A0.SetBigInt(inputs[1])
			a.B1.A1.SetBigInt(inputs[3])
			a.B1.A2.SetBigInt(inputs[5])

			var sixInv fp.Element
			sixInv.SetString("362880")
			sixInv.Inverse(&sixInv)
			c.B0.MulByElement(&a.B0, &sixInv)
			c.B1.MulByElement(&a.B1, &sixInv)

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[2])
			c.B0.A2.BigInt(outputs[4])
			c.B1.A0.BigInt(outputs[1])
			c.B1.A1.BigInt(outputs[3])
			c.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func finalExpHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This adapted from section 4.3.2 of https://eprint.iacr.org/2024/640.pdf
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var millerLoop, residueWitness bw6761.E6
			var rInv, mInv big.Int

			millerLoop.B0.A0.SetBigInt(inputs[0])
			millerLoop.B0.A1.SetBigInt(inputs[2])
			millerLoop.B0.A2.SetBigInt(inputs[4])
			millerLoop.B1.A0.SetBigInt(inputs[1])
			millerLoop.B1.A1.SetBigInt(inputs[3])
			millerLoop.B1.A2.SetBigInt(inputs[5])

			// 1. compute r-th root:
			// Exponentiate to rInv where
			// rInv = 1/r mod (p^6-1)/r
			rInv.SetString("279142441805511726233822077180198394933430419224185936052953462287387912118470357993263103168031788043160461358474005435622327506926362567154401645657309519073154383052970657693950208844465818979551693587858245321454505472049236704031061301292776853925224359757586505231126091244204292668007110271845616234279927419974150119801003450133674289144711275201991607282264849765236206295842916353255855388186086438329721887082685697023028663652777877691341551982676874308309620809049793085180324511691754953492619183755890255644855765188965000691813063771086522132765764526955251054211157804606693386854395171192876178005945476647006847460976477055233044799299417913662363985523123796056692751028712679181978298499780752966303529102009307348414562366180130429432094237007700663759126264893082917308542509779442201840676518234962495304673134599305371982876385622279935346701152286347948653741121231188575146952014672242471261647823749129902237689180055673361938161119768341970519416039779128617354778773830515364777252518313057683396662835013368967463878342754251509207391537635831891662211848811733884861792121210263430418966889668537646457064092991696527814120385172941004264289812969796992647021735186941896252860419364971543301451924917610828019341224722038007513", 10)
			residueWitness.Exp(millerLoop, &rInv)

			// 2. compute m-th root:
			// where m = (x+1 + x(x^2-x^1-1)q) / r
			// Exponentiate to mInv where
			// mInv = 1/m mod p^6-1/r
			mInv.SetString("420096572758781926988571022578549119077996267041217186563532964653013626327499627643558150289556860284699838191238508062761264485377946319676011525555582097381055209304464769241709045835179375847000286979304653199040198646948595850434830718773056593021324330541604029824826938177546414778934883707126835848724258610612114712835130017082970786784508470382396148858570586085402148355642863720286568566937773459407961735112550507047306343380386401338522186960986251395049985320677251315016812720092326581314645206610216409714397970562842517827716362494341171265008409446148022671451843025093584702610246849007545665518399731546205544005105929880663530772806759681913801835273987094997504640832304570158760940364827187477825525048007459079382410480491250884588399683894539404567701993526561088158396861020181640181843560309670937868772703282755078557149854363818903590441797744966016708880143332350534049482338696654635346189790575286999280892407997722996866724226514621504774811766428733682155766330614074143245300182851212177081558245259537898592443393875891588079021560334726750431309338787970594548465289737362624558256642461612913108676326999205533110217714096123782036214164015261929502119392490941988919030563789520985909704716341786823561745842985678563", 10)
			residueWitness.Exp(residueWitness, &mInv)

			residueWitness.B0.A0.BigInt(outputs[0])
			residueWitness.B0.A1.BigInt(outputs[2])
			residueWitness.B0.A2.BigInt(outputs[4])
			residueWitness.B1.A0.BigInt(outputs[1])
			residueWitness.B1.A1.BigInt(outputs[3])
			residueWitness.B1.A2.BigInt(outputs[5])

			return nil
		})
}
