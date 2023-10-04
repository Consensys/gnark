package compress

import (
	"bytes"
	"fmt"
)

func readHex(out *bytes.Buffer, b *[]byte, size int) error {
	for i := 0; i < size; i++ {
		var hi, lo byte
		var err error
		if hi, err = expectHexDigit(b); err != nil {
			return err
		}
		if lo, err = expectHexDigit(b); err != nil {
			return err
		}
		out.WriteByte(hi<<4 | lo)
	}
	return nil
}

func expectHexDigit(b *[]byte) (byte, error) {
	res, err := expect(b, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'D', 'e', 'f')
	if err != nil {
		return 255, err
	}
	if res >= 'a' {
		res -= 'a' - 10
	} else {
		res -= '0'
	}
	return res, nil
}

func expectStar(b *[]byte, c byte) {
	_, err := expect(b, c)
	for err == nil {
		_, err = expect(b, c)
	}
}

func expectNumber(b *[]byte) (int, error) {
	digits := []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
	var n int
	c, err := expect(b, digits...)
	n = int(c - '0')
	if err != nil {
		return n, err
	}
	c, err = expect(b, digits...)
	for err == nil {
		n *= 10
		n += int(c - '0')
		c, err = expect(b, digits...)
	}
	return n, nil
}

func expectString(b *[]byte, s string) error {
	for i := 0; i < len(s); i++ {
		c, err := expect(b, s[i])
		if err != nil {
			return err
		}
		if c != s[i] {
			return fmt.Errorf("expected %s, got %s", s, string(c))
		}
	}
	return nil
}

func expect(b *[]byte, cs ...byte) (byte, error) {
	if len(*b) == 0 {
		return 0, fmt.Errorf("end of input")
	}
	seen := (*b)[0]
	for _, c := range cs {
		if seen == c {
			*b = (*b)[1:]
			return seen, nil
		}
	}
	return seen, fmt.Errorf("unexpected %c", seen)
}
