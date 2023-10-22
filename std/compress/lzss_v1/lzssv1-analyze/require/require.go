package require

func NotEqual(unexpected, actual interface{}, message string) {
	if unexpected == actual {
		panic(message)
	}
}

func NoError(err error) {
	if err != nil {
		panic(err)
	}
}
