package lzss

import (
	"bytes"
	"errors"
	"github.com/consensys/gnark/std/compress"
	"github.com/icza/bitio"
	"io"
)

func DecompressGo(data, dict []byte) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	out.Grow(len(data)*6 + len(dict))
	in := bitio.NewReader(bytes.NewReader(data))

	var _b [2]byte
	if _, err = in.Read(_b[:]); err != nil {
		return
	}
	if version := _b[0]; version != 0 {
		return nil, errors.New("unsupported compressor version")
	}

	level := Level(_b[1])
	if level == NoCompression {
		return data[2:], nil
	}

	dict = augmentDict(dict)
	shortBackRefType, longBackRefType, dictBackRefType := initBackRefTypes(len(dict), level)

	bDict := backref{bType: dictBackRefType}
	bShort := backref{bType: shortBackRefType}
	bLong := backref{bType: longBackRefType}

	// read until startAt and write bytes as is

	s := in.TryReadByte()
	for in.TryError == nil {
		switch s {
		case symbolShort:
			// short back ref
			bShort.readFrom(in)
			for i := 0; i < bShort.length; i++ {
				out.WriteByte(out.Bytes()[out.Len()-bShort.address])
			}
		case symbolLong:
			// long back ref
			bLong.readFrom(in)
			for i := 0; i < bLong.length; i++ {
				out.WriteByte(out.Bytes()[out.Len()-bLong.address])
			}
		case symbolDict:
			// dict back ref
			bDict.readFrom(in)
			out.Write(dict[bDict.address : bDict.address+bDict.length])
		default:
			out.WriteByte(s)
		}
		s = in.TryReadByte()
	}

	return out.Bytes(), nil
}

func ReadIntoStream(data, dict []byte, level Level) compress.Stream {

	out := compress.NewStream(data, uint8(level))

	// now find out how much of the stream is padded zeros and remove them
	in := bitio.NewReader(bytes.NewReader(data))
	dict = augmentDict(dict)
	shortBackRefType, longBackRefType, dictBackRefType := initBackRefTypes(len(dict), level)
	_ = in.TryReadByte()
	levelFromData := Level(in.TryReadByte())
	outLenBits := 16
	if levelFromData == NoCompression {
		return out
	}
	if levelFromData != level {
		panic("compression mode mismatch")
	}

	s := in.TryReadByte()
	for in.TryError == nil {
		var b *backrefType
		switch s {
		case symbolShort:
			b = &shortBackRefType
		case symbolLong:
			b = &longBackRefType
		case symbolDict:
			b = &dictBackRefType
		}
		if b == nil {
			outLenBits += 8
		} else {
			_, err := in.ReadBits(b.nbBitsBackRef - 8)
			panicIfErr(err)
			outLenBits += int(b.nbBitsBackRef)
		}
		s = in.TryReadByte()
	}
	if in.TryError != io.EOF {
		panic(in.TryError)
	}

	return compress.Stream{
		D:       out.D[:outLenBits/int(level)],
		NbSymbs: out.NbSymbs,
	}
}
