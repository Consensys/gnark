package lzss_v1

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/utils"
	"strings"
)

func Decompress(c []byte, settings Settings) (d []byte, err error) {
	// d[i < 0] = settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	in := bytes.NewReader(c)
	copyBuf := make([]byte, settings.NbBytesAddress+settings.NbBytesLength)

	if settings.ReferenceTo == Compressed {
		return nil, errors.New("compressed ref not implemented")
	}
	if settings.AddressingMode == Absolute {
		return nil, errors.New("absolute addressing not implemented")
	}
	if settings.Log {
		return nil, errors.New("logging not implemented")
	}

	outAt := func(i int) byte {
		if i < 0 {
			return settings.Symbol
		}
		return out.Bytes()[i]
	}

	readBackRef := func() (offset, length int) {
		_, err = in.Read(copyBuf)
		offset = readNum(copyBuf[:settings.NbBytesAddress]) + 1
		length = readNum(copyBuf[settings.NbBytesAddress:settings.NbBytesAddress+settings.NbBytesLength]) + 1
		return
	}

	s, err := in.ReadByte()
	for err == nil {
		if s == settings.BackRefSettings.Symbol {
			offset, length := readBackRef()
			if err != nil {
				return nil, err
			}
			for i := 0; i < length; i++ {
				out.WriteByte(outAt(out.Len() - offset))
			}
		} else {
			out.WriteByte(s)
		}
		s, err = in.ReadByte()
	}

	return out.Bytes(), nil
}

func readNum(bytes []byte) int { //little endian
	var res int
	for i := len(bytes) - 1; i >= 0; i-- {
		res <<= 8
		res |= int(bytes[i])
	}
	return res
}

func DescribeCompressionActions(c []byte, settings Settings) (string, error) {
	// d[i < 0] = settings.BackRefSettings.Symbol by convention
	var out strings.Builder
	in := bytes.NewReader(c)
	copyBuf := make([]byte, settings.NbBytesAddress+settings.NbBytesLength)
	maxOffset, maxLen := -1, -1

	readBackRef := func() (offset, length int, err error) {
		_, err = in.Read(copyBuf)
		offset = readNum(copyBuf[:settings.NbBytesAddress]) + 1
		length = readNum(copyBuf[settings.NbBytesAddress:settings.NbBytesAddress+settings.NbBytesLength]) + 1
		maxOffset = utils.Max(maxOffset, offset)
		maxLen = utils.Max(maxLen, length)
		return
	}

	s, err := in.ReadByte()
	for err == nil {
		if s == settings.BackRefSettings.Symbol {
			if offset, length, err := readBackRef(); err != nil {
				return "", err
			} else {
				out.WriteString(fmt.Sprintf("\n%d:%d\n", offset, length))
			}
		} else {
			out.WriteString(fmt.Sprintf("%x", s))
		}
		s, err = in.ReadByte()
	}

	return fmt.Sprintf("maxOffset: %d, maxLen: %d\n", maxOffset, maxLen) + out.String(), nil
}
