package test_utils

import "log"

var ConditionalLoggerEnabled bool

func ConditionalLog(v ...any) {
	if ConditionalLoggerEnabled {
		log.Println(v...)
	}
}

func ConditionalLogf(format string, v ...any) {
	if ConditionalLoggerEnabled {
		log.Printf(format, v...)
	}
}
