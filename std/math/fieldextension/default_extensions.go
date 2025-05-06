package fieldextension

var defaultExtensions = map[string][]int{
	"2013265921-default": {-11, 0, 0, 0, 0, 0, 0, 0, 1}, // x^8 - 11 -- BabyBear field
	"2013265921-8":       {-11, 0, 0, 0, 0, 0, 0, 0, 1}, // x^8 - 11 -- BabyBear field
	"2013265921-4":       {-11, 0, 0, 0, 1},             // x^4 - 11 -- BabyBear field

	"2130706433-default": {-3, 0, 0, 0, 0, 0, 0, 0, 1}, // x^8 - 3 -- KoalaBear field
	"2130706433-8":       {-3, 0, 0, 0, 0, 0, 0, 0, 1}, // x^8 - 3 -- KoalaBear field
	"2130706433-4":       {-3, 0, 0, 0, 1},             // x^4 - 3 -- KoalaBear field

	"18446744069414584321-default": {-7, 0, 0, 0, 1}, // x^4 - 7 -- Goldilocks field
	"18446744069414584321-4":       {-7, 0, 0, 0, 1}, // x^4 - 7 -- Goldilocks field
	"18446744069414584321-2":       {-7, 0, 1},       // x^2 - 7 -- Goldilocks field
}
