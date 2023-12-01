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

	var settings settings
	if err = settings.readFrom(in); err != nil {
		return
	}
	if settings.version != 0 {
		return nil, errors.New("unsupported compressor version")
	}
	if settings.level == NoCompression {
		return data[2:], nil
	}

	dict = augmentDict(dict)
	shortBackRefType, longBackRefType, dictBackRefType := initBackRefTypes(len(dict), settings.level)

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

// ReadIntoStream reads the compressed data into a stream
// the stream is not padded with zeros as one obtained by a naive call to compress.NewStream may be
func ReadIntoStream(data, dict []byte, level Level) (compress.Stream, error) {

	out, err := compress.NewStream(data, uint8(level))
	if err != nil {
		return out, err
	}

	// now find out how much of the stream is padded zeros and remove them
	byteReader := bytes.NewReader(data)
	in := bitio.NewReader(byteReader)
	dict = augmentDict(dict)
	var settings settings
	if err := settings.readFrom(byteReader); err != nil {
		return out, err
	}
	shortBackRefType, longBackRefType, dictBackRefType := initBackRefTypes(len(dict), level)

	// the main job of this function is to compute the right value for outLenBits
	// so we can remove the extra zeros at the end of out
	outLenBits := settings.bitLen()
	if settings.level == NoCompression {
		return out, nil
	}
	if settings.level != level {
		return out, errors.New("compression mode mismatch")
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
			if _, err := in.ReadBits(b.nbBitsBackRef - 8); err != nil {
				return out, err
			}
			outLenBits += int(b.nbBitsBackRef)
		}
		s = in.TryReadByte()
	}
	if in.TryError != io.EOF {
		return out, in.TryError
	}

	return compress.Stream{
		D:       out.D[:outLenBits/int(level)],
		NbSymbs: out.NbSymbs,
	}, nil
}
