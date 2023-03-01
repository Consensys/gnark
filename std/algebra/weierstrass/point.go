package weierstrass

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// New returns a new [Curve] instance over the base field Base and scalar field
// Scalars defined by the curve parameters params. It returns an error if
// initialising the field emulation fails (for example, when the native field is
// too small) or when the curve parameters are incompatible with the fields.
func New[Base, Scalars emulated.FieldParams](api frontend.API, params CurveParams) (*Curve[Base, Scalars], error) {
	ba, err := emulated.NewField[Base](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	sa, err := emulated.NewField[Scalars](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	Gx := emulated.ValueOf[Base](params.Gx)
	Gy := emulated.ValueOf[Base](params.Gy)
	G3x := emulated.ValueOf[Base](params.Gmx[0])
	G3y := emulated.ValueOf[Base](params.Gmy[0])
	G5x := emulated.ValueOf[Base](params.Gmx[1])
	G5y := emulated.ValueOf[Base](params.Gmy[1])
	G7x := emulated.ValueOf[Base](params.Gmx[2])
	G7y := emulated.ValueOf[Base](params.Gmy[2])
	G2To3x := emulated.ValueOf[Base](params.Gmx[3])
	G2To3y := emulated.ValueOf[Base](params.Gmy[3])
	G2To4x := emulated.ValueOf[Base](params.Gmx[4])
	G2To4y := emulated.ValueOf[Base](params.Gmy[4])
	G2To5x := emulated.ValueOf[Base](params.Gmx[5])
	G2To5y := emulated.ValueOf[Base](params.Gmy[5])
	G2To6x := emulated.ValueOf[Base](params.Gmx[6])
	G2To6y := emulated.ValueOf[Base](params.Gmy[6])
	G2To7x := emulated.ValueOf[Base](params.Gmx[7])
	G2To7y := emulated.ValueOf[Base](params.Gmy[7])
	G2To8x := emulated.ValueOf[Base](params.Gmx[8])
	G2To8y := emulated.ValueOf[Base](params.Gmy[8])
	G2To9x := emulated.ValueOf[Base](params.Gmx[9])
	G2To9y := emulated.ValueOf[Base](params.Gmy[9])
	G2To10x := emulated.ValueOf[Base](params.Gmx[10])
	G2To10y := emulated.ValueOf[Base](params.Gmy[10])
	G2To11x := emulated.ValueOf[Base](params.Gmx[11])
	G2To11y := emulated.ValueOf[Base](params.Gmy[11])
	G2To12x := emulated.ValueOf[Base](params.Gmx[12])
	G2To12y := emulated.ValueOf[Base](params.Gmy[12])
	G2To13x := emulated.ValueOf[Base](params.Gmx[13])
	G2To13y := emulated.ValueOf[Base](params.Gmy[13])
	G2To14x := emulated.ValueOf[Base](params.Gmx[14])
	G2To14y := emulated.ValueOf[Base](params.Gmy[14])
	G2To15x := emulated.ValueOf[Base](params.Gmx[15])
	G2To15y := emulated.ValueOf[Base](params.Gmy[15])
	G2To16x := emulated.ValueOf[Base](params.Gmx[16])
	G2To16y := emulated.ValueOf[Base](params.Gmy[16])
	G2To17x := emulated.ValueOf[Base](params.Gmx[17])
	G2To17y := emulated.ValueOf[Base](params.Gmy[17])
	G2To18x := emulated.ValueOf[Base](params.Gmx[18])
	G2To18y := emulated.ValueOf[Base](params.Gmy[18])
	G2To19x := emulated.ValueOf[Base](params.Gmx[19])
	G2To19y := emulated.ValueOf[Base](params.Gmy[19])
	G2To20x := emulated.ValueOf[Base](params.Gmx[20])
	G2To20y := emulated.ValueOf[Base](params.Gmy[20])
	G2To21x := emulated.ValueOf[Base](params.Gmx[21])
	G2To21y := emulated.ValueOf[Base](params.Gmy[21])
	G2To22x := emulated.ValueOf[Base](params.Gmx[22])
	G2To22y := emulated.ValueOf[Base](params.Gmy[22])
	G2To23x := emulated.ValueOf[Base](params.Gmx[23])
	G2To23y := emulated.ValueOf[Base](params.Gmy[23])
	G2To24x := emulated.ValueOf[Base](params.Gmx[24])
	G2To24y := emulated.ValueOf[Base](params.Gmy[24])
	G2To25x := emulated.ValueOf[Base](params.Gmx[25])
	G2To25y := emulated.ValueOf[Base](params.Gmy[25])
	G2To26x := emulated.ValueOf[Base](params.Gmx[26])
	G2To26y := emulated.ValueOf[Base](params.Gmy[26])
	G2To27x := emulated.ValueOf[Base](params.Gmx[27])
	G2To27y := emulated.ValueOf[Base](params.Gmy[27])
	G2To28x := emulated.ValueOf[Base](params.Gmx[28])
	G2To28y := emulated.ValueOf[Base](params.Gmy[28])
	G2To29x := emulated.ValueOf[Base](params.Gmx[29])
	G2To29y := emulated.ValueOf[Base](params.Gmy[29])
	G2To30x := emulated.ValueOf[Base](params.Gmx[30])
	G2To30y := emulated.ValueOf[Base](params.Gmy[30])
	G2To31x := emulated.ValueOf[Base](params.Gmx[31])
	G2To31y := emulated.ValueOf[Base](params.Gmy[31])
	G2To32x := emulated.ValueOf[Base](params.Gmx[32])
	G2To32y := emulated.ValueOf[Base](params.Gmy[32])
	G2To33x := emulated.ValueOf[Base](params.Gmx[33])
	G2To33y := emulated.ValueOf[Base](params.Gmy[33])
	G2To34x := emulated.ValueOf[Base](params.Gmx[34])
	G2To34y := emulated.ValueOf[Base](params.Gmy[34])
	G2To35x := emulated.ValueOf[Base](params.Gmx[35])
	G2To35y := emulated.ValueOf[Base](params.Gmy[35])
	G2To36x := emulated.ValueOf[Base](params.Gmx[36])
	G2To36y := emulated.ValueOf[Base](params.Gmy[36])
	G2To37x := emulated.ValueOf[Base](params.Gmx[37])
	G2To37y := emulated.ValueOf[Base](params.Gmy[37])
	G2To38x := emulated.ValueOf[Base](params.Gmx[38])
	G2To38y := emulated.ValueOf[Base](params.Gmy[38])
	G2To39x := emulated.ValueOf[Base](params.Gmx[39])
	G2To39y := emulated.ValueOf[Base](params.Gmy[39])
	G2To40x := emulated.ValueOf[Base](params.Gmx[40])
	G2To40y := emulated.ValueOf[Base](params.Gmy[40])
	G2To41x := emulated.ValueOf[Base](params.Gmx[41])
	G2To41y := emulated.ValueOf[Base](params.Gmy[41])
	G2To42x := emulated.ValueOf[Base](params.Gmx[42])
	G2To42y := emulated.ValueOf[Base](params.Gmy[42])
	G2To43x := emulated.ValueOf[Base](params.Gmx[43])
	G2To43y := emulated.ValueOf[Base](params.Gmy[43])
	G2To44x := emulated.ValueOf[Base](params.Gmx[44])
	G2To44y := emulated.ValueOf[Base](params.Gmy[44])
	G2To45x := emulated.ValueOf[Base](params.Gmx[45])
	G2To45y := emulated.ValueOf[Base](params.Gmy[45])
	G2To46x := emulated.ValueOf[Base](params.Gmx[46])
	G2To46y := emulated.ValueOf[Base](params.Gmy[46])
	G2To47x := emulated.ValueOf[Base](params.Gmx[47])
	G2To47y := emulated.ValueOf[Base](params.Gmy[47])
	G2To48x := emulated.ValueOf[Base](params.Gmx[48])
	G2To48y := emulated.ValueOf[Base](params.Gmy[48])
	G2To49x := emulated.ValueOf[Base](params.Gmx[49])
	G2To49y := emulated.ValueOf[Base](params.Gmy[49])
	G2To50x := emulated.ValueOf[Base](params.Gmx[50])
	G2To50y := emulated.ValueOf[Base](params.Gmy[50])
	G2To51x := emulated.ValueOf[Base](params.Gmx[51])
	G2To51y := emulated.ValueOf[Base](params.Gmy[51])
	G2To52x := emulated.ValueOf[Base](params.Gmx[52])
	G2To52y := emulated.ValueOf[Base](params.Gmy[52])
	G2To53x := emulated.ValueOf[Base](params.Gmx[53])
	G2To53y := emulated.ValueOf[Base](params.Gmy[53])
	G2To54x := emulated.ValueOf[Base](params.Gmx[54])
	G2To54y := emulated.ValueOf[Base](params.Gmy[54])
	G2To55x := emulated.ValueOf[Base](params.Gmx[55])
	G2To55y := emulated.ValueOf[Base](params.Gmy[55])
	G2To56x := emulated.ValueOf[Base](params.Gmx[56])
	G2To56y := emulated.ValueOf[Base](params.Gmy[56])
	G2To57x := emulated.ValueOf[Base](params.Gmx[57])
	G2To57y := emulated.ValueOf[Base](params.Gmy[57])
	G2To58x := emulated.ValueOf[Base](params.Gmx[58])
	G2To58y := emulated.ValueOf[Base](params.Gmy[58])
	G2To59x := emulated.ValueOf[Base](params.Gmx[59])
	G2To59y := emulated.ValueOf[Base](params.Gmy[59])
	G2To60x := emulated.ValueOf[Base](params.Gmx[60])
	G2To60y := emulated.ValueOf[Base](params.Gmy[60])
	G2To61x := emulated.ValueOf[Base](params.Gmx[61])
	G2To61y := emulated.ValueOf[Base](params.Gmy[61])
	G2To62x := emulated.ValueOf[Base](params.Gmx[62])
	G2To62y := emulated.ValueOf[Base](params.Gmy[62])
	G2To63x := emulated.ValueOf[Base](params.Gmx[63])
	G2To63y := emulated.ValueOf[Base](params.Gmy[63])
	G2To64x := emulated.ValueOf[Base](params.Gmx[64])
	G2To64y := emulated.ValueOf[Base](params.Gmy[64])
	G2To65x := emulated.ValueOf[Base](params.Gmx[65])
	G2To65y := emulated.ValueOf[Base](params.Gmy[65])
	G2To66x := emulated.ValueOf[Base](params.Gmx[66])
	G2To66y := emulated.ValueOf[Base](params.Gmy[66])
	G2To67x := emulated.ValueOf[Base](params.Gmx[67])
	G2To67y := emulated.ValueOf[Base](params.Gmy[67])
	G2To68x := emulated.ValueOf[Base](params.Gmx[68])
	G2To68y := emulated.ValueOf[Base](params.Gmy[68])
	G2To69x := emulated.ValueOf[Base](params.Gmx[69])
	G2To69y := emulated.ValueOf[Base](params.Gmy[69])
	G2To70x := emulated.ValueOf[Base](params.Gmx[70])
	G2To70y := emulated.ValueOf[Base](params.Gmy[70])
	G2To71x := emulated.ValueOf[Base](params.Gmx[71])
	G2To71y := emulated.ValueOf[Base](params.Gmy[71])
	G2To72x := emulated.ValueOf[Base](params.Gmx[72])
	G2To72y := emulated.ValueOf[Base](params.Gmy[72])
	G2To73x := emulated.ValueOf[Base](params.Gmx[73])
	G2To73y := emulated.ValueOf[Base](params.Gmy[73])
	G2To74x := emulated.ValueOf[Base](params.Gmx[74])
	G2To74y := emulated.ValueOf[Base](params.Gmy[74])
	G2To75x := emulated.ValueOf[Base](params.Gmx[75])
	G2To75y := emulated.ValueOf[Base](params.Gmy[75])
	G2To76x := emulated.ValueOf[Base](params.Gmx[76])
	G2To76y := emulated.ValueOf[Base](params.Gmy[76])
	G2To77x := emulated.ValueOf[Base](params.Gmx[77])
	G2To77y := emulated.ValueOf[Base](params.Gmy[77])
	G2To78x := emulated.ValueOf[Base](params.Gmx[78])
	G2To78y := emulated.ValueOf[Base](params.Gmy[78])
	G2To79x := emulated.ValueOf[Base](params.Gmx[79])
	G2To79y := emulated.ValueOf[Base](params.Gmy[79])
	G2To80x := emulated.ValueOf[Base](params.Gmx[80])
	G2To80y := emulated.ValueOf[Base](params.Gmy[80])
	G2To81x := emulated.ValueOf[Base](params.Gmx[81])
	G2To81y := emulated.ValueOf[Base](params.Gmy[81])
	G2To82x := emulated.ValueOf[Base](params.Gmx[82])
	G2To82y := emulated.ValueOf[Base](params.Gmy[82])
	G2To83x := emulated.ValueOf[Base](params.Gmx[83])
	G2To83y := emulated.ValueOf[Base](params.Gmy[83])
	G2To84x := emulated.ValueOf[Base](params.Gmx[84])
	G2To84y := emulated.ValueOf[Base](params.Gmy[84])
	G2To85x := emulated.ValueOf[Base](params.Gmx[85])
	G2To85y := emulated.ValueOf[Base](params.Gmy[85])
	G2To86x := emulated.ValueOf[Base](params.Gmx[86])
	G2To86y := emulated.ValueOf[Base](params.Gmy[86])
	G2To87x := emulated.ValueOf[Base](params.Gmx[87])
	G2To87y := emulated.ValueOf[Base](params.Gmy[87])
	G2To88x := emulated.ValueOf[Base](params.Gmx[88])
	G2To88y := emulated.ValueOf[Base](params.Gmy[88])
	G2To89x := emulated.ValueOf[Base](params.Gmx[89])
	G2To89y := emulated.ValueOf[Base](params.Gmy[89])
	G2To90x := emulated.ValueOf[Base](params.Gmx[90])
	G2To90y := emulated.ValueOf[Base](params.Gmy[90])
	G2To91x := emulated.ValueOf[Base](params.Gmx[91])
	G2To91y := emulated.ValueOf[Base](params.Gmy[91])
	G2To92x := emulated.ValueOf[Base](params.Gmx[92])
	G2To92y := emulated.ValueOf[Base](params.Gmy[92])
	G2To93x := emulated.ValueOf[Base](params.Gmx[93])
	G2To93y := emulated.ValueOf[Base](params.Gmy[93])
	G2To94x := emulated.ValueOf[Base](params.Gmx[94])
	G2To94y := emulated.ValueOf[Base](params.Gmy[94])
	G2To95x := emulated.ValueOf[Base](params.Gmx[95])
	G2To95y := emulated.ValueOf[Base](params.Gmy[95])
	G2To96x := emulated.ValueOf[Base](params.Gmx[96])
	G2To96y := emulated.ValueOf[Base](params.Gmy[96])
	G2To97x := emulated.ValueOf[Base](params.Gmx[97])
	G2To97y := emulated.ValueOf[Base](params.Gmy[97])
	G2To98x := emulated.ValueOf[Base](params.Gmx[98])
	G2To98y := emulated.ValueOf[Base](params.Gmy[98])
	G2To99x := emulated.ValueOf[Base](params.Gmx[99])
	G2To99y := emulated.ValueOf[Base](params.Gmy[99])
	G2To100x := emulated.ValueOf[Base](params.Gmx[100])
	G2To100y := emulated.ValueOf[Base](params.Gmy[100])
	G2To101x := emulated.ValueOf[Base](params.Gmx[101])
	G2To101y := emulated.ValueOf[Base](params.Gmy[101])
	G2To102x := emulated.ValueOf[Base](params.Gmx[102])
	G2To102y := emulated.ValueOf[Base](params.Gmy[102])
	G2To103x := emulated.ValueOf[Base](params.Gmx[103])
	G2To103y := emulated.ValueOf[Base](params.Gmy[103])
	G2To104x := emulated.ValueOf[Base](params.Gmx[104])
	G2To104y := emulated.ValueOf[Base](params.Gmy[104])
	G2To105x := emulated.ValueOf[Base](params.Gmx[105])
	G2To105y := emulated.ValueOf[Base](params.Gmy[105])
	G2To106x := emulated.ValueOf[Base](params.Gmx[106])
	G2To106y := emulated.ValueOf[Base](params.Gmy[106])
	G2To107x := emulated.ValueOf[Base](params.Gmx[107])
	G2To107y := emulated.ValueOf[Base](params.Gmy[107])
	G2To108x := emulated.ValueOf[Base](params.Gmx[108])
	G2To108y := emulated.ValueOf[Base](params.Gmy[108])
	G2To109x := emulated.ValueOf[Base](params.Gmx[109])
	G2To109y := emulated.ValueOf[Base](params.Gmy[109])
	G2To110x := emulated.ValueOf[Base](params.Gmx[110])
	G2To110y := emulated.ValueOf[Base](params.Gmy[110])
	G2To111x := emulated.ValueOf[Base](params.Gmx[111])
	G2To111y := emulated.ValueOf[Base](params.Gmy[111])
	G2To112x := emulated.ValueOf[Base](params.Gmx[112])
	G2To112y := emulated.ValueOf[Base](params.Gmy[112])
	G2To113x := emulated.ValueOf[Base](params.Gmx[113])
	G2To113y := emulated.ValueOf[Base](params.Gmy[113])
	G2To114x := emulated.ValueOf[Base](params.Gmx[114])
	G2To114y := emulated.ValueOf[Base](params.Gmy[114])
	G2To115x := emulated.ValueOf[Base](params.Gmx[115])
	G2To115y := emulated.ValueOf[Base](params.Gmy[115])
	G2To116x := emulated.ValueOf[Base](params.Gmx[116])
	G2To116y := emulated.ValueOf[Base](params.Gmy[116])
	G2To117x := emulated.ValueOf[Base](params.Gmx[117])
	G2To117y := emulated.ValueOf[Base](params.Gmy[117])
	G2To118x := emulated.ValueOf[Base](params.Gmx[118])
	G2To118y := emulated.ValueOf[Base](params.Gmy[118])
	G2To119x := emulated.ValueOf[Base](params.Gmx[119])
	G2To119y := emulated.ValueOf[Base](params.Gmy[119])
	G2To120x := emulated.ValueOf[Base](params.Gmx[120])
	G2To120y := emulated.ValueOf[Base](params.Gmy[120])
	G2To121x := emulated.ValueOf[Base](params.Gmx[121])
	G2To121y := emulated.ValueOf[Base](params.Gmy[121])
	G2To122x := emulated.ValueOf[Base](params.Gmx[122])
	G2To122y := emulated.ValueOf[Base](params.Gmy[122])
	G2To123x := emulated.ValueOf[Base](params.Gmx[123])
	G2To123y := emulated.ValueOf[Base](params.Gmy[123])
	G2To124x := emulated.ValueOf[Base](params.Gmx[124])
	G2To124y := emulated.ValueOf[Base](params.Gmy[124])
	G2To125x := emulated.ValueOf[Base](params.Gmx[125])
	G2To125y := emulated.ValueOf[Base](params.Gmy[125])
	G2To126x := emulated.ValueOf[Base](params.Gmx[126])
	G2To126y := emulated.ValueOf[Base](params.Gmy[126])
	G2To127x := emulated.ValueOf[Base](params.Gmx[127])
	G2To127y := emulated.ValueOf[Base](params.Gmy[127])
	G2To128x := emulated.ValueOf[Base](params.Gmx[128])
	G2To128y := emulated.ValueOf[Base](params.Gmy[128])
	G2To129x := emulated.ValueOf[Base](params.Gmx[129])
	G2To129y := emulated.ValueOf[Base](params.Gmy[129])
	G2To130x := emulated.ValueOf[Base](params.Gmx[130])
	G2To130y := emulated.ValueOf[Base](params.Gmy[130])
	G2To131x := emulated.ValueOf[Base](params.Gmx[131])
	G2To131y := emulated.ValueOf[Base](params.Gmy[131])
	G2To132x := emulated.ValueOf[Base](params.Gmx[132])
	G2To132y := emulated.ValueOf[Base](params.Gmy[132])
	G2To133x := emulated.ValueOf[Base](params.Gmx[133])
	G2To133y := emulated.ValueOf[Base](params.Gmy[133])
	G2To134x := emulated.ValueOf[Base](params.Gmx[134])
	G2To134y := emulated.ValueOf[Base](params.Gmy[134])
	G2To135x := emulated.ValueOf[Base](params.Gmx[135])
	G2To135y := emulated.ValueOf[Base](params.Gmy[135])
	G2To136x := emulated.ValueOf[Base](params.Gmx[136])
	G2To136y := emulated.ValueOf[Base](params.Gmy[136])
	G2To137x := emulated.ValueOf[Base](params.Gmx[137])
	G2To137y := emulated.ValueOf[Base](params.Gmy[137])
	G2To138x := emulated.ValueOf[Base](params.Gmx[138])
	G2To138y := emulated.ValueOf[Base](params.Gmy[138])
	G2To139x := emulated.ValueOf[Base](params.Gmx[139])
	G2To139y := emulated.ValueOf[Base](params.Gmy[139])
	G2To140x := emulated.ValueOf[Base](params.Gmx[140])
	G2To140y := emulated.ValueOf[Base](params.Gmy[140])
	G2To141x := emulated.ValueOf[Base](params.Gmx[141])
	G2To141y := emulated.ValueOf[Base](params.Gmy[141])
	G2To142x := emulated.ValueOf[Base](params.Gmx[142])
	G2To142y := emulated.ValueOf[Base](params.Gmy[142])
	G2To143x := emulated.ValueOf[Base](params.Gmx[143])
	G2To143y := emulated.ValueOf[Base](params.Gmy[143])
	G2To144x := emulated.ValueOf[Base](params.Gmx[144])
	G2To144y := emulated.ValueOf[Base](params.Gmy[144])
	G2To145x := emulated.ValueOf[Base](params.Gmx[145])
	G2To145y := emulated.ValueOf[Base](params.Gmy[145])
	G2To146x := emulated.ValueOf[Base](params.Gmx[146])
	G2To146y := emulated.ValueOf[Base](params.Gmy[146])
	G2To147x := emulated.ValueOf[Base](params.Gmx[147])
	G2To147y := emulated.ValueOf[Base](params.Gmy[147])
	G2To148x := emulated.ValueOf[Base](params.Gmx[148])
	G2To148y := emulated.ValueOf[Base](params.Gmy[148])
	G2To149x := emulated.ValueOf[Base](params.Gmx[149])
	G2To149y := emulated.ValueOf[Base](params.Gmy[149])
	G2To150x := emulated.ValueOf[Base](params.Gmx[150])
	G2To150y := emulated.ValueOf[Base](params.Gmy[150])
	G2To151x := emulated.ValueOf[Base](params.Gmx[151])
	G2To151y := emulated.ValueOf[Base](params.Gmy[151])
	G2To152x := emulated.ValueOf[Base](params.Gmx[152])
	G2To152y := emulated.ValueOf[Base](params.Gmy[152])
	G2To153x := emulated.ValueOf[Base](params.Gmx[153])
	G2To153y := emulated.ValueOf[Base](params.Gmy[153])
	G2To154x := emulated.ValueOf[Base](params.Gmx[154])
	G2To154y := emulated.ValueOf[Base](params.Gmy[154])
	G2To155x := emulated.ValueOf[Base](params.Gmx[155])
	G2To155y := emulated.ValueOf[Base](params.Gmy[155])
	G2To156x := emulated.ValueOf[Base](params.Gmx[156])
	G2To156y := emulated.ValueOf[Base](params.Gmy[156])
	G2To157x := emulated.ValueOf[Base](params.Gmx[157])
	G2To157y := emulated.ValueOf[Base](params.Gmy[157])
	G2To158x := emulated.ValueOf[Base](params.Gmx[158])
	G2To158y := emulated.ValueOf[Base](params.Gmy[158])
	G2To159x := emulated.ValueOf[Base](params.Gmx[159])
	G2To159y := emulated.ValueOf[Base](params.Gmy[159])
	G2To160x := emulated.ValueOf[Base](params.Gmx[160])
	G2To160y := emulated.ValueOf[Base](params.Gmy[160])
	G2To161x := emulated.ValueOf[Base](params.Gmx[161])
	G2To161y := emulated.ValueOf[Base](params.Gmy[161])
	G2To162x := emulated.ValueOf[Base](params.Gmx[162])
	G2To162y := emulated.ValueOf[Base](params.Gmy[162])
	G2To163x := emulated.ValueOf[Base](params.Gmx[163])
	G2To163y := emulated.ValueOf[Base](params.Gmy[163])
	G2To164x := emulated.ValueOf[Base](params.Gmx[164])
	G2To164y := emulated.ValueOf[Base](params.Gmy[164])
	G2To165x := emulated.ValueOf[Base](params.Gmx[165])
	G2To165y := emulated.ValueOf[Base](params.Gmy[165])
	G2To166x := emulated.ValueOf[Base](params.Gmx[166])
	G2To166y := emulated.ValueOf[Base](params.Gmy[166])
	G2To167x := emulated.ValueOf[Base](params.Gmx[167])
	G2To167y := emulated.ValueOf[Base](params.Gmy[167])
	G2To168x := emulated.ValueOf[Base](params.Gmx[168])
	G2To168y := emulated.ValueOf[Base](params.Gmy[168])
	G2To169x := emulated.ValueOf[Base](params.Gmx[169])
	G2To169y := emulated.ValueOf[Base](params.Gmy[169])
	G2To170x := emulated.ValueOf[Base](params.Gmx[170])
	G2To170y := emulated.ValueOf[Base](params.Gmy[170])
	G2To171x := emulated.ValueOf[Base](params.Gmx[171])
	G2To171y := emulated.ValueOf[Base](params.Gmy[171])
	G2To172x := emulated.ValueOf[Base](params.Gmx[172])
	G2To172y := emulated.ValueOf[Base](params.Gmy[172])
	G2To173x := emulated.ValueOf[Base](params.Gmx[173])
	G2To173y := emulated.ValueOf[Base](params.Gmy[173])
	G2To174x := emulated.ValueOf[Base](params.Gmx[174])
	G2To174y := emulated.ValueOf[Base](params.Gmy[174])
	G2To175x := emulated.ValueOf[Base](params.Gmx[175])
	G2To175y := emulated.ValueOf[Base](params.Gmy[175])
	G2To176x := emulated.ValueOf[Base](params.Gmx[176])
	G2To176y := emulated.ValueOf[Base](params.Gmy[176])
	G2To177x := emulated.ValueOf[Base](params.Gmx[177])
	G2To177y := emulated.ValueOf[Base](params.Gmy[177])
	G2To178x := emulated.ValueOf[Base](params.Gmx[178])
	G2To178y := emulated.ValueOf[Base](params.Gmy[178])
	G2To179x := emulated.ValueOf[Base](params.Gmx[179])
	G2To179y := emulated.ValueOf[Base](params.Gmy[179])
	G2To180x := emulated.ValueOf[Base](params.Gmx[180])
	G2To180y := emulated.ValueOf[Base](params.Gmy[180])
	G2To181x := emulated.ValueOf[Base](params.Gmx[181])
	G2To181y := emulated.ValueOf[Base](params.Gmy[181])
	G2To182x := emulated.ValueOf[Base](params.Gmx[182])
	G2To182y := emulated.ValueOf[Base](params.Gmy[182])
	G2To183x := emulated.ValueOf[Base](params.Gmx[183])
	G2To183y := emulated.ValueOf[Base](params.Gmy[183])
	G2To184x := emulated.ValueOf[Base](params.Gmx[184])
	G2To184y := emulated.ValueOf[Base](params.Gmy[184])
	G2To185x := emulated.ValueOf[Base](params.Gmx[185])
	G2To185y := emulated.ValueOf[Base](params.Gmy[185])
	G2To186x := emulated.ValueOf[Base](params.Gmx[186])
	G2To186y := emulated.ValueOf[Base](params.Gmy[186])
	G2To187x := emulated.ValueOf[Base](params.Gmx[187])
	G2To187y := emulated.ValueOf[Base](params.Gmy[187])
	G2To188x := emulated.ValueOf[Base](params.Gmx[188])
	G2To188y := emulated.ValueOf[Base](params.Gmy[188])
	G2To189x := emulated.ValueOf[Base](params.Gmx[189])
	G2To189y := emulated.ValueOf[Base](params.Gmy[189])
	G2To190x := emulated.ValueOf[Base](params.Gmx[190])
	G2To190y := emulated.ValueOf[Base](params.Gmy[190])
	G2To191x := emulated.ValueOf[Base](params.Gmx[191])
	G2To191y := emulated.ValueOf[Base](params.Gmy[191])
	G2To192x := emulated.ValueOf[Base](params.Gmx[192])
	G2To192y := emulated.ValueOf[Base](params.Gmy[192])
	G2To193x := emulated.ValueOf[Base](params.Gmx[193])
	G2To193y := emulated.ValueOf[Base](params.Gmy[193])
	G2To194x := emulated.ValueOf[Base](params.Gmx[194])
	G2To194y := emulated.ValueOf[Base](params.Gmy[194])
	G2To195x := emulated.ValueOf[Base](params.Gmx[195])
	G2To195y := emulated.ValueOf[Base](params.Gmy[195])
	G2To196x := emulated.ValueOf[Base](params.Gmx[196])
	G2To196y := emulated.ValueOf[Base](params.Gmy[196])
	G2To197x := emulated.ValueOf[Base](params.Gmx[197])
	G2To197y := emulated.ValueOf[Base](params.Gmy[197])
	G2To198x := emulated.ValueOf[Base](params.Gmx[198])
	G2To198y := emulated.ValueOf[Base](params.Gmy[198])
	G2To199x := emulated.ValueOf[Base](params.Gmx[199])
	G2To199y := emulated.ValueOf[Base](params.Gmy[199])
	G2To200x := emulated.ValueOf[Base](params.Gmx[200])
	G2To200y := emulated.ValueOf[Base](params.Gmy[200])
	G2To201x := emulated.ValueOf[Base](params.Gmx[201])
	G2To201y := emulated.ValueOf[Base](params.Gmy[201])
	G2To202x := emulated.ValueOf[Base](params.Gmx[202])
	G2To202y := emulated.ValueOf[Base](params.Gmy[202])
	G2To203x := emulated.ValueOf[Base](params.Gmx[203])
	G2To203y := emulated.ValueOf[Base](params.Gmy[203])
	G2To204x := emulated.ValueOf[Base](params.Gmx[204])
	G2To204y := emulated.ValueOf[Base](params.Gmy[204])
	G2To205x := emulated.ValueOf[Base](params.Gmx[205])
	G2To205y := emulated.ValueOf[Base](params.Gmy[205])
	G2To206x := emulated.ValueOf[Base](params.Gmx[206])
	G2To206y := emulated.ValueOf[Base](params.Gmy[206])
	G2To207x := emulated.ValueOf[Base](params.Gmx[207])
	G2To207y := emulated.ValueOf[Base](params.Gmy[207])
	G2To208x := emulated.ValueOf[Base](params.Gmx[208])
	G2To208y := emulated.ValueOf[Base](params.Gmy[208])
	G2To209x := emulated.ValueOf[Base](params.Gmx[209])
	G2To209y := emulated.ValueOf[Base](params.Gmy[209])
	G2To210x := emulated.ValueOf[Base](params.Gmx[210])
	G2To210y := emulated.ValueOf[Base](params.Gmy[210])
	G2To211x := emulated.ValueOf[Base](params.Gmx[211])
	G2To211y := emulated.ValueOf[Base](params.Gmy[211])
	G2To212x := emulated.ValueOf[Base](params.Gmx[212])
	G2To212y := emulated.ValueOf[Base](params.Gmy[212])
	G2To213x := emulated.ValueOf[Base](params.Gmx[213])
	G2To213y := emulated.ValueOf[Base](params.Gmy[213])
	G2To214x := emulated.ValueOf[Base](params.Gmx[214])
	G2To214y := emulated.ValueOf[Base](params.Gmy[214])
	G2To215x := emulated.ValueOf[Base](params.Gmx[215])
	G2To215y := emulated.ValueOf[Base](params.Gmy[215])
	G2To216x := emulated.ValueOf[Base](params.Gmx[216])
	G2To216y := emulated.ValueOf[Base](params.Gmy[216])
	G2To217x := emulated.ValueOf[Base](params.Gmx[217])
	G2To217y := emulated.ValueOf[Base](params.Gmy[217])
	G2To218x := emulated.ValueOf[Base](params.Gmx[218])
	G2To218y := emulated.ValueOf[Base](params.Gmy[218])
	G2To219x := emulated.ValueOf[Base](params.Gmx[219])
	G2To219y := emulated.ValueOf[Base](params.Gmy[219])
	G2To220x := emulated.ValueOf[Base](params.Gmx[220])
	G2To220y := emulated.ValueOf[Base](params.Gmy[220])
	G2To221x := emulated.ValueOf[Base](params.Gmx[221])
	G2To221y := emulated.ValueOf[Base](params.Gmy[221])
	G2To222x := emulated.ValueOf[Base](params.Gmx[222])
	G2To222y := emulated.ValueOf[Base](params.Gmy[222])
	G2To223x := emulated.ValueOf[Base](params.Gmx[223])
	G2To223y := emulated.ValueOf[Base](params.Gmy[223])
	G2To224x := emulated.ValueOf[Base](params.Gmx[224])
	G2To224y := emulated.ValueOf[Base](params.Gmy[224])
	G2To225x := emulated.ValueOf[Base](params.Gmx[225])
	G2To225y := emulated.ValueOf[Base](params.Gmy[225])
	G2To226x := emulated.ValueOf[Base](params.Gmx[226])
	G2To226y := emulated.ValueOf[Base](params.Gmy[226])
	G2To227x := emulated.ValueOf[Base](params.Gmx[227])
	G2To227y := emulated.ValueOf[Base](params.Gmy[227])
	G2To228x := emulated.ValueOf[Base](params.Gmx[228])
	G2To228y := emulated.ValueOf[Base](params.Gmy[228])
	G2To229x := emulated.ValueOf[Base](params.Gmx[229])
	G2To229y := emulated.ValueOf[Base](params.Gmy[229])
	G2To230x := emulated.ValueOf[Base](params.Gmx[230])
	G2To230y := emulated.ValueOf[Base](params.Gmy[230])
	G2To231x := emulated.ValueOf[Base](params.Gmx[231])
	G2To231y := emulated.ValueOf[Base](params.Gmy[231])
	G2To232x := emulated.ValueOf[Base](params.Gmx[232])
	G2To232y := emulated.ValueOf[Base](params.Gmy[232])
	G2To233x := emulated.ValueOf[Base](params.Gmx[233])
	G2To233y := emulated.ValueOf[Base](params.Gmy[233])
	G2To234x := emulated.ValueOf[Base](params.Gmx[234])
	G2To234y := emulated.ValueOf[Base](params.Gmy[234])
	G2To235x := emulated.ValueOf[Base](params.Gmx[235])
	G2To235y := emulated.ValueOf[Base](params.Gmy[235])
	G2To236x := emulated.ValueOf[Base](params.Gmx[236])
	G2To236y := emulated.ValueOf[Base](params.Gmy[236])
	G2To237x := emulated.ValueOf[Base](params.Gmx[237])
	G2To237y := emulated.ValueOf[Base](params.Gmy[237])
	G2To238x := emulated.ValueOf[Base](params.Gmx[238])
	G2To238y := emulated.ValueOf[Base](params.Gmy[238])
	G2To239x := emulated.ValueOf[Base](params.Gmx[239])
	G2To239y := emulated.ValueOf[Base](params.Gmy[239])
	G2To240x := emulated.ValueOf[Base](params.Gmx[240])
	G2To240y := emulated.ValueOf[Base](params.Gmy[240])
	G2To241x := emulated.ValueOf[Base](params.Gmx[241])
	G2To241y := emulated.ValueOf[Base](params.Gmy[241])
	G2To242x := emulated.ValueOf[Base](params.Gmx[242])
	G2To242y := emulated.ValueOf[Base](params.Gmy[242])
	G2To243x := emulated.ValueOf[Base](params.Gmx[243])
	G2To243y := emulated.ValueOf[Base](params.Gmy[243])
	G2To244x := emulated.ValueOf[Base](params.Gmx[244])
	G2To244y := emulated.ValueOf[Base](params.Gmy[244])
	G2To245x := emulated.ValueOf[Base](params.Gmx[245])
	G2To245y := emulated.ValueOf[Base](params.Gmy[245])
	G2To246x := emulated.ValueOf[Base](params.Gmx[246])
	G2To246y := emulated.ValueOf[Base](params.Gmy[246])
	G2To247x := emulated.ValueOf[Base](params.Gmx[247])
	G2To247y := emulated.ValueOf[Base](params.Gmy[247])
	G2To248x := emulated.ValueOf[Base](params.Gmx[248])
	G2To248y := emulated.ValueOf[Base](params.Gmy[248])
	G2To249x := emulated.ValueOf[Base](params.Gmx[249])
	G2To249y := emulated.ValueOf[Base](params.Gmy[249])
	G2To250x := emulated.ValueOf[Base](params.Gmx[250])
	G2To250y := emulated.ValueOf[Base](params.Gmy[250])
	G2To251x := emulated.ValueOf[Base](params.Gmx[251])
	G2To251y := emulated.ValueOf[Base](params.Gmy[251])
	G2To252x := emulated.ValueOf[Base](params.Gmx[252])
	G2To252y := emulated.ValueOf[Base](params.Gmy[252])
	G2To253x := emulated.ValueOf[Base](params.Gmx[253])
	G2To253y := emulated.ValueOf[Base](params.Gmy[253])
	G2To254x := emulated.ValueOf[Base](params.Gmx[254])
	G2To254y := emulated.ValueOf[Base](params.Gmy[254])
	G2To255x := emulated.ValueOf[Base](params.Gmx[255])
	G2To255y := emulated.ValueOf[Base](params.Gmy[255])
	return &Curve[Base, Scalars]{
		params:    params,
		api:       api,
		baseApi:   ba,
		scalarApi: sa,
		g: AffinePoint[Base]{
			X: Gx,
			Y: Gy,
		},
		gm: [256]AffinePoint[Base]{
			{X: G3x, Y: G3y},
			{X: G5x, Y: G5y},
			{X: G7x, Y: G7y},
			{X: G2To3x, Y: G2To3y},
			{X: G2To4x, Y: G2To4y},
			{X: G2To5x, Y: G2To5y},
			{X: G2To6x, Y: G2To6y},
			{X: G2To7x, Y: G2To7y},
			{X: G2To8x, Y: G2To8y},
			{X: G2To9x, Y: G2To9y},
			{X: G2To10x, Y: G2To10y},
			{X: G2To11x, Y: G2To11y},
			{X: G2To12x, Y: G2To12y},
			{X: G2To13x, Y: G2To13y},
			{X: G2To14x, Y: G2To14y},
			{X: G2To15x, Y: G2To15y},
			{X: G2To16x, Y: G2To16y},
			{X: G2To17x, Y: G2To17y},
			{X: G2To18x, Y: G2To18y},
			{X: G2To19x, Y: G2To19y},
			{X: G2To20x, Y: G2To20y},
			{X: G2To21x, Y: G2To21y},
			{X: G2To22x, Y: G2To22y},
			{X: G2To23x, Y: G2To23y},
			{X: G2To24x, Y: G2To24y},
			{X: G2To25x, Y: G2To25y},
			{X: G2To26x, Y: G2To26y},
			{X: G2To27x, Y: G2To27y},
			{X: G2To28x, Y: G2To28y},
			{X: G2To29x, Y: G2To29y},
			{X: G2To30x, Y: G2To30y},
			{X: G2To31x, Y: G2To31y},
			{X: G2To32x, Y: G2To32y},
			{X: G2To33x, Y: G2To33y},
			{X: G2To34x, Y: G2To34y},
			{X: G2To35x, Y: G2To35y},
			{X: G2To36x, Y: G2To36y},
			{X: G2To37x, Y: G2To37y},
			{X: G2To38x, Y: G2To38y},
			{X: G2To39x, Y: G2To39y},
			{X: G2To40x, Y: G2To40y},
			{X: G2To41x, Y: G2To41y},
			{X: G2To42x, Y: G2To42y},
			{X: G2To43x, Y: G2To43y},
			{X: G2To44x, Y: G2To44y},
			{X: G2To45x, Y: G2To45y},
			{X: G2To46x, Y: G2To46y},
			{X: G2To47x, Y: G2To47y},
			{X: G2To48x, Y: G2To48y},
			{X: G2To49x, Y: G2To49y},
			{X: G2To50x, Y: G2To50y},
			{X: G2To51x, Y: G2To51y},
			{X: G2To52x, Y: G2To52y},
			{X: G2To53x, Y: G2To53y},
			{X: G2To54x, Y: G2To54y},
			{X: G2To55x, Y: G2To55y},
			{X: G2To56x, Y: G2To56y},
			{X: G2To57x, Y: G2To57y},
			{X: G2To58x, Y: G2To58y},
			{X: G2To59x, Y: G2To59y},
			{X: G2To60x, Y: G2To60y},
			{X: G2To61x, Y: G2To61y},
			{X: G2To62x, Y: G2To62y},
			{X: G2To63x, Y: G2To63y},
			{X: G2To64x, Y: G2To64y},
			{X: G2To65x, Y: G2To65y},
			{X: G2To66x, Y: G2To66y},
			{X: G2To67x, Y: G2To67y},
			{X: G2To68x, Y: G2To68y},
			{X: G2To69x, Y: G2To69y},
			{X: G2To70x, Y: G2To70y},
			{X: G2To71x, Y: G2To71y},
			{X: G2To72x, Y: G2To72y},
			{X: G2To73x, Y: G2To73y},
			{X: G2To74x, Y: G2To74y},
			{X: G2To75x, Y: G2To75y},
			{X: G2To76x, Y: G2To76y},
			{X: G2To77x, Y: G2To77y},
			{X: G2To78x, Y: G2To78y},
			{X: G2To79x, Y: G2To79y},
			{X: G2To80x, Y: G2To80y},
			{X: G2To81x, Y: G2To81y},
			{X: G2To82x, Y: G2To82y},
			{X: G2To83x, Y: G2To83y},
			{X: G2To84x, Y: G2To84y},
			{X: G2To85x, Y: G2To85y},
			{X: G2To86x, Y: G2To86y},
			{X: G2To87x, Y: G2To87y},
			{X: G2To88x, Y: G2To88y},
			{X: G2To89x, Y: G2To89y},
			{X: G2To90x, Y: G2To90y},
			{X: G2To91x, Y: G2To91y},
			{X: G2To92x, Y: G2To92y},
			{X: G2To93x, Y: G2To93y},
			{X: G2To94x, Y: G2To94y},
			{X: G2To95x, Y: G2To95y},
			{X: G2To96x, Y: G2To96y},
			{X: G2To97x, Y: G2To97y},
			{X: G2To98x, Y: G2To98y},
			{X: G2To99x, Y: G2To99y},
			{X: G2To100x, Y: G2To100y},
			{X: G2To101x, Y: G2To101y},
			{X: G2To102x, Y: G2To102y},
			{X: G2To103x, Y: G2To103y},
			{X: G2To104x, Y: G2To104y},
			{X: G2To105x, Y: G2To105y},
			{X: G2To106x, Y: G2To106y},
			{X: G2To107x, Y: G2To107y},
			{X: G2To108x, Y: G2To108y},
			{X: G2To109x, Y: G2To109y},
			{X: G2To110x, Y: G2To110y},
			{X: G2To111x, Y: G2To111y},
			{X: G2To112x, Y: G2To112y},
			{X: G2To113x, Y: G2To113y},
			{X: G2To114x, Y: G2To114y},
			{X: G2To115x, Y: G2To115y},
			{X: G2To116x, Y: G2To116y},
			{X: G2To117x, Y: G2To117y},
			{X: G2To118x, Y: G2To118y},
			{X: G2To119x, Y: G2To119y},
			{X: G2To120x, Y: G2To120y},
			{X: G2To121x, Y: G2To121y},
			{X: G2To122x, Y: G2To122y},
			{X: G2To123x, Y: G2To123y},
			{X: G2To124x, Y: G2To124y},
			{X: G2To125x, Y: G2To125y},
			{X: G2To126x, Y: G2To126y},
			{X: G2To127x, Y: G2To127y},
			{X: G2To128x, Y: G2To128y},
			{X: G2To129x, Y: G2To129y},
			{X: G2To130x, Y: G2To130y},
			{X: G2To131x, Y: G2To131y},
			{X: G2To132x, Y: G2To132y},
			{X: G2To133x, Y: G2To133y},
			{X: G2To134x, Y: G2To134y},
			{X: G2To135x, Y: G2To135y},
			{X: G2To136x, Y: G2To136y},
			{X: G2To137x, Y: G2To137y},
			{X: G2To138x, Y: G2To138y},
			{X: G2To139x, Y: G2To139y},
			{X: G2To140x, Y: G2To140y},
			{X: G2To141x, Y: G2To141y},
			{X: G2To142x, Y: G2To142y},
			{X: G2To143x, Y: G2To143y},
			{X: G2To144x, Y: G2To144y},
			{X: G2To145x, Y: G2To145y},
			{X: G2To146x, Y: G2To146y},
			{X: G2To147x, Y: G2To147y},
			{X: G2To148x, Y: G2To148y},
			{X: G2To149x, Y: G2To149y},
			{X: G2To150x, Y: G2To150y},
			{X: G2To151x, Y: G2To151y},
			{X: G2To152x, Y: G2To152y},
			{X: G2To153x, Y: G2To153y},
			{X: G2To154x, Y: G2To154y},
			{X: G2To155x, Y: G2To155y},
			{X: G2To156x, Y: G2To156y},
			{X: G2To157x, Y: G2To157y},
			{X: G2To158x, Y: G2To158y},
			{X: G2To159x, Y: G2To159y},
			{X: G2To160x, Y: G2To160y},
			{X: G2To161x, Y: G2To161y},
			{X: G2To162x, Y: G2To162y},
			{X: G2To163x, Y: G2To163y},
			{X: G2To164x, Y: G2To164y},
			{X: G2To165x, Y: G2To165y},
			{X: G2To166x, Y: G2To166y},
			{X: G2To167x, Y: G2To167y},
			{X: G2To168x, Y: G2To168y},
			{X: G2To169x, Y: G2To169y},
			{X: G2To170x, Y: G2To170y},
			{X: G2To171x, Y: G2To171y},
			{X: G2To172x, Y: G2To172y},
			{X: G2To173x, Y: G2To173y},
			{X: G2To174x, Y: G2To174y},
			{X: G2To175x, Y: G2To175y},
			{X: G2To176x, Y: G2To176y},
			{X: G2To177x, Y: G2To177y},
			{X: G2To178x, Y: G2To178y},
			{X: G2To179x, Y: G2To179y},
			{X: G2To180x, Y: G2To180y},
			{X: G2To181x, Y: G2To181y},
			{X: G2To182x, Y: G2To182y},
			{X: G2To183x, Y: G2To183y},
			{X: G2To184x, Y: G2To184y},
			{X: G2To185x, Y: G2To185y},
			{X: G2To186x, Y: G2To186y},
			{X: G2To187x, Y: G2To187y},
			{X: G2To188x, Y: G2To188y},
			{X: G2To189x, Y: G2To189y},
			{X: G2To190x, Y: G2To190y},
			{X: G2To191x, Y: G2To191y},
			{X: G2To192x, Y: G2To192y},
			{X: G2To193x, Y: G2To193y},
			{X: G2To194x, Y: G2To194y},
			{X: G2To195x, Y: G2To195y},
			{X: G2To196x, Y: G2To196y},
			{X: G2To197x, Y: G2To197y},
			{X: G2To198x, Y: G2To198y},
			{X: G2To199x, Y: G2To199y},
			{X: G2To200x, Y: G2To200y},
			{X: G2To201x, Y: G2To201y},
			{X: G2To202x, Y: G2To202y},
			{X: G2To203x, Y: G2To203y},
			{X: G2To204x, Y: G2To204y},
			{X: G2To205x, Y: G2To205y},
			{X: G2To206x, Y: G2To206y},
			{X: G2To207x, Y: G2To207y},
			{X: G2To208x, Y: G2To208y},
			{X: G2To209x, Y: G2To209y},
			{X: G2To210x, Y: G2To210y},
			{X: G2To211x, Y: G2To211y},
			{X: G2To212x, Y: G2To212y},
			{X: G2To213x, Y: G2To213y},
			{X: G2To214x, Y: G2To214y},
			{X: G2To215x, Y: G2To215y},
			{X: G2To216x, Y: G2To216y},
			{X: G2To217x, Y: G2To217y},
			{X: G2To218x, Y: G2To218y},
			{X: G2To219x, Y: G2To219y},
			{X: G2To220x, Y: G2To220y},
			{X: G2To221x, Y: G2To221y},
			{X: G2To222x, Y: G2To222y},
			{X: G2To223x, Y: G2To223y},
			{X: G2To224x, Y: G2To224y},
			{X: G2To225x, Y: G2To225y},
			{X: G2To226x, Y: G2To226y},
			{X: G2To227x, Y: G2To227y},
			{X: G2To228x, Y: G2To228y},
			{X: G2To229x, Y: G2To229y},
			{X: G2To230x, Y: G2To230y},
			{X: G2To231x, Y: G2To231y},
			{X: G2To232x, Y: G2To232y},
			{X: G2To233x, Y: G2To233y},
			{X: G2To234x, Y: G2To234y},
			{X: G2To235x, Y: G2To235y},
			{X: G2To236x, Y: G2To236y},
			{X: G2To237x, Y: G2To237y},
			{X: G2To238x, Y: G2To238y},
			{X: G2To239x, Y: G2To239y},
			{X: G2To240x, Y: G2To240y},
			{X: G2To241x, Y: G2To241y},
			{X: G2To242x, Y: G2To242y},
			{X: G2To243x, Y: G2To243y},
			{X: G2To244x, Y: G2To244y},
			{X: G2To245x, Y: G2To245y},
			{X: G2To246x, Y: G2To246y},
			{X: G2To247x, Y: G2To247y},
			{X: G2To248x, Y: G2To248y},
			{X: G2To249x, Y: G2To249y},
			{X: G2To250x, Y: G2To250y},
			{X: G2To251x, Y: G2To251y},
			{X: G2To252x, Y: G2To252y},
			{X: G2To253x, Y: G2To253y},
			{X: G2To254x, Y: G2To254y},
			{X: G2To255x, Y: G2To255y},
		},

		a:    emulated.ValueOf[Base](params.A),
		addA: params.A.Cmp(big.NewInt(0)) != 0,
	}, nil
}

// Curve is an initialised curve which allows performing group operations.
type Curve[Base, Scalars emulated.FieldParams] struct {
	// params is the parameters of the curve
	params CurveParams
	// api is the native api, we construct it ourselves to be sure
	api frontend.API
	// baseApi is the api for point operations
	baseApi *emulated.Field[Base]
	// scalarApi is the api for scalar operations
	scalarApi *emulated.Field[Scalars]

	// g is the generator (base point) of the curve.
	g AffinePoint[Base]

	// gm are the pre-computed multiples the generator (base point) of the curve.
	gm [256]AffinePoint[Base]

	a    emulated.Element[Base]
	addA bool
}

// Generator returns the base point of the curve. The method does not copy and
// modifying the returned element leads to undefined behaviour!
func (c *Curve[B, S]) Generator() *AffinePoint[B] {
	return &c.g
}

// GeneratorMultiples returns the pre-computed multiples of the base point of the curve. The method does not copy and
// modifying the returned element leads to undefined behaviour!
func (c *Curve[B, S]) GeneratorMultiples() [256]AffinePoint[B] {
	return c.gm
}

// AffinePoint represents a point on the elliptic curve. We do not check that
// the point is actually on the curve.
type AffinePoint[Base emulated.FieldParams] struct {
	X, Y emulated.Element[Base]
}

// Neg returns an inverse of p. It doesn't modify p.
func (c *Curve[B, S]) Neg(p *AffinePoint[B]) *AffinePoint[B] {
	return &AffinePoint[B]{
		X: p.X,
		Y: *c.baseApi.Neg(&p.Y),
	}
}

// AssertIsEqual asserts that p and q are the same point.
func (c *Curve[B, S]) AssertIsEqual(p, q *AffinePoint[B]) {
	c.baseApi.AssertIsEqual(&p.X, &q.X)
	c.baseApi.AssertIsEqual(&p.Y, &q.Y)
}

// Add adds p and q and returns it. It doesn't modify p nor q.
// It uses incomplete formulas in affine coordinates.
// The points p and q should be different and nonzero (neutral element).
func (c *Curve[B, S]) Add(p, q *AffinePoint[B]) *AffinePoint[B] {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := c.baseApi.Sub(&q.Y, &p.Y)
	qxpx := c.baseApi.Sub(&q.X, &p.X)
	λ := c.baseApi.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	λλ := c.baseApi.MulMod(λ, λ)
	qxpx = c.baseApi.Add(&p.X, &q.X)
	xr := c.baseApi.Sub(λλ, qxpx)

	// p.y = λ(p.x-r.x) - p.y
	pxrx := c.baseApi.Sub(&p.X, xr)
	λpxrx := c.baseApi.MulMod(λ, pxrx)
	yr := c.baseApi.Sub(λpxrx, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(yr),
	}
}

// Double doubles p and return it. It doesn't modify p.
// It uses affine coordinates.
func (c *Curve[B, S]) Double(p *AffinePoint[B]) *AffinePoint[B] {

	// compute λ = (3p.x²+a)/2*p.y, here we assume a=0 (j invariant 0 curve)
	xx3a := c.baseApi.MulMod(&p.X, &p.X)
	xx3a = c.baseApi.MulConst(xx3a, big.NewInt(3))
	if c.addA {
		xx3a = c.baseApi.Add(xx3a, &c.a)
	}
	y2 := c.baseApi.MulConst(&p.Y, big.NewInt(2))
	λ := c.baseApi.Div(xx3a, y2)

	// xr = λ²-2p.x
	x2 := c.baseApi.MulConst(&p.X, big.NewInt(2))
	λλ := c.baseApi.MulMod(λ, λ)
	xr := c.baseApi.Sub(λλ, x2)

	// yr = λ(p-xr) - p.y
	pxrx := c.baseApi.Sub(&p.X, xr)
	λpxrx := c.baseApi.MulMod(λ, pxrx)
	yr := c.baseApi.Sub(λpxrx, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(yr),
	}
}

// Triple triples p and return it. It follows [ELM03] (Section 3.1).
// Saves the computation of the y coordinate of 2p as it is used only in the computation of λ2,
// which can be computed as
//
// diffλ2 = -λ1-2*p.y/(x2-p.x) instead.
//
// It doesn't modify p.
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
func (c *Curve[B, S]) Triple(p *AffinePoint[B]) *AffinePoint[B] {

	// compute λ1 = (3p.x²+a)/2p.y, here we assume a=0 (j invariant 0 curve)
	xx := c.baseApi.MulMod(&p.X, &p.X)
	xx = c.baseApi.MulConst(xx, big.NewInt(3))
	if c.addA {
		xx = c.baseApi.Add(xx, &c.a)
	}
	y2 := c.baseApi.MulConst(&p.Y, big.NewInt(2))
	λ1 := c.baseApi.Div(xx, y2)

	// xr = λ1²-2p.x
	x2 := c.baseApi.MulConst(&p.X, big.NewInt(2))
	λ1λ1 := c.baseApi.MulMod(λ1, λ1)
	x2 = c.baseApi.Sub(λ1λ1, x2)

	// ommit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := c.baseApi.Sub(&p.X, x2)
	λ2 := c.baseApi.Div(y2, x1x2)
	λ2 = c.baseApi.Sub(λ2, λ1)

	// xr = λ²-p.x-x2
	λ2λ2 := c.baseApi.MulMod(λ2, λ2)
	qxrx := c.baseApi.Add(x2, &p.X)
	xr := c.baseApi.Sub(λ2λ2, qxrx)

	// yr = λ(p.x-xr) - p.y
	pxrx := c.baseApi.Sub(&p.X, xr)
	λ2pxrx := c.baseApi.MulMod(λ2, pxrx)
	yr := c.baseApi.Sub(λ2pxrx, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(yr),
	}
}

// DoubleAndAdd computes 2p+q as (p+q)+p. It follows [ELM03] (Section 3.1)
// Saves the computation of the y coordinate of p+q as it is used only in the computation of λ2,
// which can be computed as
//
// diffλ2 = -λ1-2*p.y/(x2-p.x)
//
// instead. It doesn't modify p nor q.
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
func (c *Curve[B, S]) DoubleAndAdd(p, q *AffinePoint[B]) *AffinePoint[B] {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := c.baseApi.Sub(&q.Y, &p.Y)
	xqxp := c.baseApi.Sub(&q.X, &p.X)
	λ1 := c.baseApi.Div(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	λ1λ1 := c.baseApi.MulMod(λ1, λ1)
	xqxp = c.baseApi.Add(&p.X, &q.X)
	x2 := c.baseApi.Sub(λ1λ1, xqxp)

	// ommit y2 computation
	// compute λ2 = -λ1-2*p.y/(x2-p.x)
	ypyp := c.baseApi.Add(&p.Y, &p.Y)
	x2xp := c.baseApi.Sub(x2, &p.X)
	λ2 := c.baseApi.Div(ypyp, x2xp)
	λ2 = c.baseApi.Add(λ1, λ2)
	λ2 = c.baseApi.Neg(λ2)

	// compute x3 =λ2²-p.x-x3
	λ2λ2 := c.baseApi.MulMod(λ2, λ2)
	x3 := c.baseApi.Sub(λ2λ2, &p.X)
	x3 = c.baseApi.Sub(x3, x2)

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := c.baseApi.Sub(&p.X, x3)
	y3 = c.baseApi.Mul(λ2, y3)
	y3 = c.baseApi.Sub(y3, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(x3),
		Y: *c.baseApi.Reduce(y3),
	}

}

// Select selects between p and q given the selector b. If b == 1, then returns
// p and q otherwise.
func (c *Curve[B, S]) Select(b frontend.Variable, p, q *AffinePoint[B]) *AffinePoint[B] {
	x := c.baseApi.Select(b, &p.X, &q.X)
	y := c.baseApi.Select(b, &p.Y, &q.Y)
	return &AffinePoint[B]{
		X: *x,
		Y: *y,
	}
}

// Lookup2 performs a 2-bit lookup between i0, i1, i2, i3 based on bits b0
// and b1. Returns:
//   - i0 if b0=0 and b1=0,
//   - i1 if b0=1 and b1=0,
//   - i2 if b0=0 and b1=1,
//   - i3 if b0=1 and b1=1.
func (c *Curve[B, S]) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 *AffinePoint[B]) *AffinePoint[B] {
	x := c.baseApi.Lookup2(b0, b1, &i0.X, &i1.X, &i2.X, &i3.X)
	y := c.baseApi.Lookup2(b0, b1, &i0.Y, &i1.Y, &i2.Y, &i3.Y)
	return &AffinePoint[B]{
		X: *x,
		Y: *y,
	}
}

// ScalarMul computes s * p and returns it. It doesn't modify p nor s.
//
// It computes the standard little-endian variable-base double-and-add algorithm
// [HMV04] (Algorithm 3.26).
//
// Since we use incomplete formulas for the addition law, we need to start with
// a non-zero accumulator point (res). To do this, we skip the LSB (bit at
// position 0) and proceed assuming it was 1. At the end, we conditionally
// subtract the initial value (p) if LSB is 1. We also handle the bits at
// positions 1, n-2 and n-1 outside of the loop to optimize the number of
// constraints using [ELM03] (Section 3.1)
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
// [HMV04]: Guide to Elliptic Curve Cryptography
func (c *Curve[B, S]) ScalarMul(p *AffinePoint[B], s *emulated.Element[S]) *AffinePoint[B] {
	var st S
	sr := c.scalarApi.Reduce(s)
	sBits := c.scalarApi.ToBits(sr)
	n := st.Modulus().BitLen()

	// i = 1
	tmp := c.Triple(p)
	res := c.Select(sBits[1], tmp, p)
	acc := c.Add(tmp, p)

	for i := 2; i <= n-3; i++ {
		tmp := c.Add(res, acc)
		res = c.Select(sBits[i], tmp, res)
		acc = c.Double(acc)
	}

	// i = n-2
	tmp = c.Add(res, acc)
	res = c.Select(sBits[n-2], tmp, res)

	// i = n-1
	tmp = c.DoubleAndAdd(acc, res)
	res = c.Select(sBits[n-1], tmp, res)

	// i = 0
	tmp = c.Add(res, c.Neg(p))
	res = c.Select(sBits[0], res, tmp)

	return res
}

// ScalarMulBase computes s * g and returns it, where g is the fixed generator.
// It doesn't modify s.
//
// It computes the standard little-endian fixed-base double-and-add algorithm
// [HMV04] (Algorithm 3.26).
//
// The method proceeds similarly to ScalarMul but with the points [2^i]g
// precomputed.  The bits at positions 1 and 2 are handled outside of the loop
// to optimize the number of constraints using a Lookup2 with pre-computed
// [3]g, [5]g and [7]g points.
func (c *Curve[B, S]) ScalarMulBase(s *emulated.Element[S]) *AffinePoint[B] {
	g := c.Generator()
	gm := c.GeneratorMultiples()

	var st S
	sr := c.scalarApi.Reduce(s)
	sBits := c.scalarApi.ToBits(sr)

	// i = 1, 2
	// gm[0] = 3g, gm[1] = 5g, gm[2] = 7g
	res := c.Lookup2(sBits[1], sBits[2], g, &gm[0], &gm[1], &gm[2])

	for i := 3; i < st.Modulus().BitLen(); i++ {
		// gm[i] = [2^i]g
		tmp := c.Add(res, &gm[i])
		res = c.Select(sBits[i], tmp, res)
	}

	// i = 0
	tmp := c.Add(res, c.Neg(g))
	res = c.Select(sBits[0], res, tmp)

	return res
}
