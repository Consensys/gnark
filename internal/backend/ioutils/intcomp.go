package ioutils

import (
	"encoding/binary"
	"io"

	"github.com/ronanh/intcomp"
)

// CompressAndWriteUints32 compresses a slice of uint32 and writes it to w.
// It returns the input buffer (possibly extended) for future use.
func CompressAndWriteUints32(w io.Writer, input []uint32, buffer []uint32) ([]uint32, error) {
	buffer = buffer[:0]
	buffer = intcomp.CompressUint32(input, buffer)
	if err := binary.Write(w, binary.LittleEndian, uint64(len(buffer))); err != nil {
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

// CompressAndWriteUints64 compresses a slice of uint64 and writes it to w.
// It returns the input buffer (possibly extended) for future use.
func CompressAndWriteUints64(w io.Writer, input []uint64) error {
	buffer := intcomp.CompressUint64(input, nil)
	if err := binary.Write(w, binary.LittleEndian, uint64(len(buffer))); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, buffer)
}

// ReadAndDecompressUints32 reads a compressed slice of uint32 from r and decompresses it.
// It returns the number of bytes read, the decompressed slice and an error.
func ReadAndDecompressUints32(r io.Reader) (int, []uint32, error) {
	var length uint64
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return 0, nil, err
	}
	buffer := make([]uint32, length)
	if err := binary.Read(r, binary.LittleEndian, buffer); err != nil {
		return 8, nil, err
	}
	return 8 + 4*int(length), intcomp.UncompressUint32(buffer, nil), nil
}

// ReadAndDecompressUints64 reads a compressed slice of uint64 from r and decompresses it.
// It returns the number of bytes read, the decompressed slice and an error.
func ReadAndDecompressUints64(r io.Reader) (int, []uint64, error) {
	var length uint64
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return 0, nil, err
	}
	buffer := make([]uint64, length)
	if err := binary.Read(r, binary.LittleEndian, buffer); err != nil {
		return 8, nil, err
	}
	return 8 + 8*int(length), intcomp.UncompressUint64(buffer, nil), nil
}
