package lzss_v2

import (
	"bytes"
	"github.com/consensys/gnark/std/compress"
	"github.com/icza/bitio"
)

func DecompressGo(data, dict []byte) (d []byte, err error) {
	// d[i < 0] = Settings.BackRefSettings.Symbol by convention
	var out bytes.Buffer
	out.Grow(len(data)*6 + len(dict))
	in := bitio.NewReader(bytes.NewReader(data))

	dict = augmentDict(dict)
	dictBackRefType := initDictBackref(dict)

	bDict := backref{bType: dictBackRefType}
	bShort := backref{bType: shortBackRefType}
	bLong := backref{bType: longBackRefType}

	// read until startAt and write bytes as is
	// out.Write(dict)

	s := in.TryReadByte()
	for in.TryError == nil {
		switch s {
		case symbolShort:
			// short back ref
			bShort.readFrom(in)
			for i := 0; i < bShort.length; i++ {
				out.WriteByte(out.Bytes()[out.Len()-bShort.offset])
			}
		case symbolLong:
			// long back ref
			bLong.readFrom(in)
			for i := 0; i < bLong.length; i++ {
				out.WriteByte(out.Bytes()[out.Len()-bLong.offset])
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

	return out.Bytes(), nil
}

func ReadIntoStream(data, dict []byte) compress.Stream {
	in := bitio.NewReader(bytes.NewReader(data))

	dict = augmentDict(dict)
	dictBackRefType := initDictBackref(dict)

	wordLen := compress.Gcd(8,
		longBackRefType.nbBitsAddress, longBackRefType.nbBitsLength,
		shortBackRefType.nbBitsAddress, shortBackRefType.nbBitsLength,
		dictBackRefType.nbBitsAddress, dictBackRefType.nbBitsLength)

	out := compress.Stream{
		NbSymbs: 1 << wordLen,
	}

	bDict := backref{bType: dictBackRefType}
	bShort := backref{bType: shortBackRefType}
	bLong := backref{bType: longBackRefType}

	s := in.TryReadByte()

	for in.TryError == nil {
		out.WriteNum(int(s), 8)

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
		b.readFrom(in)
		out.WriteNum(b.length, int(b.bType.nbBitsLength))
		out.WriteNum(b.offset, int(b.bType.nbBitsAddress))

		s = in.TryReadByte()
	}
	return out
}
