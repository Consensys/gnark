package sumcheck

import "github.com/consensys/gnark/frontend"

// @ThomasPiellard my struggle with the current fiatshamir transcript implementation is that the user of the sumcheck protocol must provide one of the bindings, so the transcript object
//must be provided to the Prove and Verify functions. However, the user doesn't a-priori know the number of required challenges
//(they COULD know, but it would go against the abstraction Prove/Verify are meant to provide to expect them to know)
//Generally, the challenge (no pun intended) stems from the non-triviality of the number of rounds in sumcheck and hence in GKR

type ArithmeticTranscript interface {
	Update(...interface{})
	Next(...interface{}) frontend.Variable
	NextN(int, ...interface{}) []frontend.Variable
}
