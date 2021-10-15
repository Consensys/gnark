package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

type TestingOption struct {
	backends             []backend.ID
	curves               []ecc.ID
	witnessSerialization bool
	proverOpts           []func(opt *backend.ProverOption) error
}

func WithBackends(b backend.ID, backends ...backend.ID) func(opt *TestingOption) error {
	return func(opt *TestingOption) error {
		opt.backends = []backend.ID{b}
		opt.backends = append(opt.backends, backends...)
		return nil
	}
}

func WithCurves(c ecc.ID, curves ...ecc.ID) func(opt *TestingOption) error {
	return func(opt *TestingOption) error {
		opt.curves = []ecc.ID{c}
		opt.curves = append(opt.curves, curves...)
		return nil
	}
}

func NoSerialization() func(opt *TestingOption) error {
	return func(opt *TestingOption) error {
		opt.witnessSerialization = false
		return nil
	}
}

func WithProverOpts(proverOpts ...func(opt *backend.ProverOption) error) func(opt *TestingOption) error {
	return func(opt *TestingOption) error {
		opt.proverOpts = proverOpts
		return nil
	}
}
