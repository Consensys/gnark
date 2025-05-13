package fieldextension

import "math/big"

var (
	bi0   = big.NewInt(0)
	bi1   = big.NewInt(1)
	biN3  = big.NewInt(-3)
	biN7  = big.NewInt(-7)
	biN11 = big.NewInt(-11)
)

// defaultExtensions gives some default extensions for the small fields defined in gnark.
// They are used when the extension is not explicitly given.
var defaultExtensions = map[string][]*big.Int{
	"2013265921-default": {biN11, bi0, bi0, bi0, bi0, bi0, bi0, bi0, bi1}, // x^8 - 11 -- BabyBear field
	"2013265921-8":       {biN11, bi0, bi0, bi0, bi0, bi0, bi0, bi0, bi1}, // x^8 - 11 -- BabyBear field
	"2013265921-4":       {biN11, bi0, bi0, bi0, bi1},                     // x^4 - 11 -- BabyBear field

	"2130706433-default": {biN3, bi0, bi0, bi0, bi0, bi0, bi0, bi0, bi1}, // x^8 - 3 -- KoalaBear field
	"2130706433-8":       {biN3, bi0, bi0, bi0, bi0, bi0, bi0, bi0, bi1}, // x^8 - 3 -- KoalaBear field
	"2130706433-4":       {biN3, bi0, bi0, bi0, bi1},                     // x^4 - 3 -- KoalaBear field

	"18446744069414584321-default": {biN7, bi0, bi0, bi0, bi1}, // x^4 - 7 -- Goldilocks field
	"18446744069414584321-4":       {biN7, bi0, bi0, bi0, bi1}, // x^4 - 7 -- Goldilocks field
	"18446744069414584321-2":       {biN7, bi0, bi1},           // x^2 - 7 -- Goldilocks field
}
