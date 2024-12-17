package io

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// RoundTripCheck is a helper to check that a serialization round trip is correct.
// It writes the object to a buffer, then reads it back and checks that the reconstructed object is equal to the original.
// It supports both io.ReaderFrom and UnsafeReaderFrom interfaces (to object)
// It also supports both io.WriterTo and WriterRawTo interfaces (from object)
func RoundTripCheck(from any, to func() any) error {
	var buf bytes.Buffer

	reconstruct := func(written int64) error {
		// if builder implements io.ReaderFrom
		if r, ok := to().(io.ReaderFrom); ok {
			read, err := r.ReadFrom(bytes.NewReader(buf.Bytes()))
			if err != nil {
				return err
			}
			if err = equal(from, r); err != nil {
				return fmt.Errorf("ReadFrom: %w", err)
			}
			if written != read {
				return errors.New("bytes written / read don't match")
			}
		}

		// if builder implements gnarkio.UnsafeReaderFrom
		if r, ok := to().(UnsafeReaderFrom); ok {
			read, err := r.UnsafeReadFrom(bytes.NewReader(buf.Bytes()))
			if err != nil {
				return err
			}
			if err = equal(from, r); err != nil {
				return fmt.Errorf("UnsafeReadFrom: %w", err)
			}
			if written != read {
				return errors.New("bytes written / read don't match")
			}
		}
		return nil
	}

	// if from implements io.WriterTo
	if w, ok := from.(io.WriterTo); ok {
		written, err := w.WriteTo(&buf)
		if err != nil {
			return err
		}

		//fmt.Println(base64.StdEncoding.EncodeToString(buf.Bytes()[:written]))

		if err := reconstruct(written); err != nil {
			return err
		}
	}

	buf.Reset()

	// if from implements gnarkio.WriterRawTo
	if w, ok := from.(WriterRawTo); ok {
		written, err := w.WriteRawTo(&buf)
		if err != nil {
			return err
		}

		if err := reconstruct(written); err != nil {
			return err
		}
	}

	return nil
}

func DumpRoundTripCheck(from any, to func() any) error {
	var buf bytes.Buffer

	if err := from.(BinaryDumper).WriteDump(&buf); err != nil {
		return err
	}

	r := to().(BinaryDumper)
	if err := r.ReadDump(bytes.NewReader(buf.Bytes())); err != nil {
		return err
	}
	if err := equal(from, r); err != nil {
		return fmt.Errorf("ReadDump: %w", err)
	}
	return nil
}

func equal(a, b any) error {
	// check for a custom Equal method
	aV := reflect.ValueOf(a)
	eq := aV.MethodByName("Equal")
	if eq.IsValid() {
		res := eq.Call([]reflect.Value{reflect.ValueOf(b)})
		if len(res) != 1 {
			return errors.New("`Equal` method must return a single bool")
		}
		if res[0].Bool() {
			return nil
		}
		return errors.New("reconstructed object does not match the original (custom Equal)")
	}
	if reflect.DeepEqual(a, b) {
		return nil
	}
	return errors.New("reconstructed object does not match the original (reflect.DeepEqual)")
}
