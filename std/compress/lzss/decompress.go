package lzss

import (
	"bytes"
	"errors"
	"io"

	"github.com/consensys/gnark/std/compress"
	"github.com/icza/bitio"
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
		return data[1:], nil
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
	in := bitio.NewReader(bytes.NewReader(data))

	wordLen := int(level)

	dict = augmentDict(dict)
	shortBackRefType, longBackRefType, dictBackRefType := initBackRefTypes(len(dict), level)

	bDict := backref{bType: dictBackRefType}
	bShort := backref{bType: shortBackRefType}
	bLong := backref{bType: longBackRefType}

	levelFromData := Level(in.TryReadByte())
	if levelFromData != NoCompression && levelFromData != level {
		panic("compression mode mismatch")
	}

	out := compress.Stream{
		NbSymbs: 1 << wordLen,
	}

	out.WriteNum(int(levelFromData), 8/wordLen)

	s := in.TryReadByte()

	for in.TryError == nil {
		out.WriteNum(int(s), 8/wordLen)

		var b *backref
		switch s {
		case symbolShort:
			// short back ref
			b = &bShort
		case symbolLong:
			// long back ref
			b = &bLong
		case symbolDict:
			// dict back ref
			b = &bDict
		}
		if b != nil && levelFromData != NoCompression {
			b.readFrom(in)
			address := b.address
			if b != &bDict {
				address--
			}
			out.WriteNum(b.length-1, int(b.bType.nbBitsLength)/wordLen)
			out.WriteNum(address, int(b.bType.nbBitsAddress)/wordLen)
		}

		s = in.TryReadByte()
	}
	if in.TryError != io.EOF {
		panic(in.TryError)
	}
	return out
}
