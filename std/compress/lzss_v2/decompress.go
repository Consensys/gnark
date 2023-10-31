package lzss_v2

import (
	"bytes"

	"github.com/icza/bitio"
)

func Decompress(data, dict []byte) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	out.Grow(len(data)*6 + len(dict))
	in := bitio.NewReader(bytes.NewReader(data))

	dict = augmentDict(dict)
	dictBackRefType := initDictBackref(dict)

	bDict := backref{bType: dictBackRefType}
	bShort := backref{bType: shortBackRefType}
	bLong := backref{bType: longBackRefType}

	outAt := func(i int) byte {
		if i < 0 {
			panic("shouldn't happen")
		}
		return out.Bytes()[i]
	}

	// read until startAt and write bytes as is
	out.Write(dict)

	s := in.TryReadByte()
	for in.TryError == nil {
		switch s {
		case symbolShort:
			// short back ref
			bShort.readFrom(in)
			for i := 0; i < bShort.length; i++ {
				out.WriteByte(outAt(out.Len() - bShort.offset))
			}
		case symbolLong:
			// long back ref
			bLong.readFrom(in)
			for i := 0; i < bLong.length; i++ {
				out.WriteByte(outAt(out.Len() - bLong.offset))
			}
		case symbolDict:
			// dict back ref
			bDict.readFrom(in)
			out.Write(dict[bDict.offset : bDict.offset+bDict.length])
			// for i := 0; i < bDict.length; i++ {
			// 	out.WriteByte(outAt(out.Len() - bDict.offset))
			// }
		default:
			out.WriteByte(s)
		}
		s = in.TryReadByte()
	}

	return out.Bytes()[len(dict):], nil
}
