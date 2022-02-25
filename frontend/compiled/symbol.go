package compiled

type Symbol interface {
	AssertIsSet()
	IsConstant() bool
}
