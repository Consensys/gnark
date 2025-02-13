package sw_bw6761

import (
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		finalExpHint,
		pairingCheckHint,
	}
}

func finalExpHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This adapted from section 4.3.2 of https://eprint.iacr.org/2024/640.pdf
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {

			var millerLoop bw6761.E6
			millerLoop.B0.A0.SetBigInt(inputs[0])
			millerLoop.B0.A1.SetBigInt(inputs[2])
			millerLoop.B0.A2.SetBigInt(inputs[4])
			millerLoop.B1.A0.SetBigInt(inputs[1])
			millerLoop.B1.A1.SetBigInt(inputs[3])
			millerLoop.B1.A2.SetBigInt(inputs[5])

			// m = (x₀³-x₀²+1-p(x₀+1)) / r
			// mInv = 1/m mod p^6-1/r
			var mInv big.Int
			mInv.SetString("420096572758781926988571022578549119077996267041217186563532964653013626327499627643558150289556860284699838191238508062761264485377946319676011525555582097381055209304464769241709045835179375847000286979304653199040198646948595850434830718773056593021324330541604029824826938177546414778934883707126835848724258610612114712835130017082970786784508470382396148858570586085402148355642863720286568566937773459407961735112550507047306343380386401338522186960986251395049985320677251315016812720092326581314645206610216409714397970562842517827716362494341171265008409446148022671451843025093584702610246849007545665518399731546205544005105929880663530772806759681913801835273987094997504640832304570158760940364827187477825525048007459079382410480491250884588399683894539404567701993526561088158396861020181640181843560309670937868772703282755078557149854363818903590441797744966016708880143332350534049482338696654635346189790575286999280892407997722996866724226514621504774811766428733682155766330614074143245300182851212177081558245259537898592443393875891588079021560334726750431309338787970594548465289737362624558256642461612913108676326999205533110217714096123782036214164015261929502119392490941988919030563789520985909704716341786823561745842985678563", 10)

			residueWitness := finalExpWitness(&millerLoop, &mInv)

			residueWitness.B0.A0.BigInt(outputs[0])
			residueWitness.B0.A1.BigInt(outputs[2])
			residueWitness.B0.A2.BigInt(outputs[4])
			residueWitness.B1.A0.BigInt(outputs[1])
			residueWitness.B1.A1.BigInt(outputs[3])
			residueWitness.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func pairingCheckHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This adapted from section 4.3.2 of https://eprint.iacr.org/2024/640.pdf
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var P bw6761.G1Affine
			var Q bw6761.G2Affine
			n := len(inputs)
			p := make([]bw6761.G1Affine, 0, n/4)
			q := make([]bw6761.G2Affine, 0, n/4)
			for k := 0; k < n/4+1; k += 2 {
				P.X.SetBigInt(inputs[k])
				P.Y.SetBigInt(inputs[k+1])
				p = append(p, P)
			}
			for k := n / 2; k < n; k += 2 {
				Q.X.SetBigInt(inputs[k])
				Q.Y.SetBigInt(inputs[k+1])
				q = append(q, Q)
			}

			millerLoop, err := bw6761.MillerLoopDirect(p, q)
			if err != nil {
				return err
			}

			// m = (x₀+1+p(x₀³-x₀²-x₀)) / r
			// mInv = 1/m mod p^6-1/r
			var mInv big.Int
			mInv.SetString("105300887666978464659709343582542432109497460559010677145223399327335567156593762277982229043678237863242655241846768823344862796112034076814141083092751207576412334798103601349742476585775877619451019850167305863473223932142842098178714149254582966792063312581807532675011404956270444910983750120675327025908192761069674135173328190635728173483753211505851991073745950587829640934449952514784880889959559541546684726344944253403018397996950965921029567425987659358091464001225755716260618839676545930683009926269854751616319103606509390667378268460666742713527948268373325914395974070631687649214144656759247037859773349886114399692016935966157297580328600396352321897692663748248168657388300690175586203114387947411720168269584172401784701771662759756974275902513788431327670950496435721956320875507468132703494465092748348925165286946843554008708392819919707156205920861214337368776935547492934209453494196115576830279851512338758088097719490141268227027970070242059962020992385206924254152017997017283665944910844784993588814611604460594039341562723060932582754994971346320340801549001828241339646153773031765187339622798156846331769418880530957782348437016822638577491500694745694281480857816937650066502281171825041093314285283892479458782481150957342407", 10)

			residueWitnessInv := finalExpWitness(&millerLoop, &mInv)
			residueWitnessInv.Inverse(&residueWitnessInv)

			residueWitnessInv.B0.A0.BigInt(outputs[0])
			residueWitnessInv.B0.A1.BigInt(outputs[2])
			residueWitnessInv.B0.A2.BigInt(outputs[4])
			residueWitnessInv.B1.A0.BigInt(outputs[1])
			residueWitnessInv.B1.A1.BigInt(outputs[3])
			residueWitnessInv.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func finalExpWitness(millerLoop *bw6761.E6, mInv *big.Int) (residueWitness bw6761.E6) {

	var rInv big.Int
	// 1. compute r-th root:
	// Exponentiate to rInv where
	// rInv = 1/r mod (p^6-1)/r
	rInv.SetString("279142441805511726233822077180198394933430419224185936052953462287387912118470357993263103168031788043160461358474005435622327506926362567154401645657309519073154383052970657693950208844465818979551693587858245321454505472049236704031061301292776853925224359757586505231126091244204292668007110271845616234279927419974150119801003450133674289144711275201991607282264849765236206295842916353255855388186086438329721887082685697023028663652777877691341551982676874308309620809049793085180324511691754953492619183755890255644855765188965000691813063771086522132765764526955251054211157804606693386854395171192876178005945476647006847460976477055233044799299417913662363985523123796056692751028712679181978298499780752966303529102009307348414562366180130429432094237007700663759126264893082917308542509779442201840676518234962495304673134599305371982876385622279935346701152286347948653741121231188575146952014672242471261647823749129902237689180055673361938161119768341970519416039779128617354778773830515364777252518313057683396662835013368967463878342754251509207391537635831891662211848811733884861792121210263430418966889668537646457064092991696527814120385172941004264289812969796992647021735186941896252860419364971543301451924917610828019341224722038007513", 10)
	residueWitness.Exp(*millerLoop, &rInv)

	// 2. compute m-th root:
	residueWitness.Exp(residueWitness, mInv)

	return residueWitness
}
