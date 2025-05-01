package gkr

// RegisterGateSettings for the std package as well as per-curve implementations
type RegisterGateSettings struct {
	// TODO once unigate is achieved, move back to std
	SolvableVar               int
	NoSolvableVarVerification bool
	NoDegreeVerification      bool
	Degree                    int

	PerCurveImpls []any
}

// DefaultRegisterGateSettings when user provides no values
func DefaultRegisterGateSettings() RegisterGateSettings {
	return RegisterGateSettings{
		SolvableVar:               -1,
		NoSolvableVarVerification: false,
		NoDegreeVerification:      false,
		Degree:                    -1,
	}
}

type RegisterGateOption func(*RegisterGateSettings)

// WithSolvableVar gives the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will return an error if it cannot verify that this claim is correct.
func WithSolvableVar(solvableVar int) RegisterGateOption {
	return func(settings *RegisterGateSettings) {
		settings.SolvableVar = solvableVar
	}
}

// WithUnverifiedSolvableVar sets the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not verify that the given index is correct.
func WithUnverifiedSolvableVar(solvableVar int) RegisterGateOption {
	return func(settings *RegisterGateSettings) {
		settings.NoSolvableVarVerification = true
		settings.SolvableVar = solvableVar
	}
}

// WithNoSolvableVar sets the gate as having no variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not check the correctness of this claim.
func WithNoSolvableVar() RegisterGateOption {
	return func(settings *RegisterGateSettings) {
		settings.SolvableVar = -1
		settings.NoSolvableVarVerification = true
	}
}

// WithUnverifiedDegree sets the degree of the gate. RegisterGate will not verify that the given degree is correct.
func WithUnverifiedDegree(degree int) RegisterGateOption {
	return func(settings *RegisterGateSettings) {
		settings.NoDegreeVerification = true
		settings.Degree = degree
	}
}

// WithDegree sets the degree of the gate. RegisterGate will return an error if the degree is not correct.
func WithDegree(degree int) RegisterGateOption {
	return func(settings *RegisterGateSettings) {
		settings.Degree = degree
	}
}

func NewRegisterGateSettings(opts ...RegisterGateOption) RegisterGateSettings {
	settings := DefaultRegisterGateSettings()
	for _, opt := range opts {
		opt(&settings)
	}
	return settings
}
