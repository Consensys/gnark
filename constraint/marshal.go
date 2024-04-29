package constraint

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"

	"github.com/consensys/gnark/internal/backend/ioutils"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sync/errgroup"
)

func (cs *System) ToBytes() ([]byte, error) {
	var calldata, instructions, levels []byte
	var g errgroup.Group
	g.Go(func() error {
		calldata = cs.calldataToBytes()
		return nil
	})
	g.Go(func() error {
		var err error
		instructions, err = cs.instructionsToBytes()
		return err
	})
	g.Go(func() error {
		var err error
		levels, err = cs.levelsToBytes()
		return err
	})
	body, err := cs.toBytes()
	if err != nil {
		return nil, err
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// header
	h := header{
		levelsLen:       uint64(len(levels)),
		instructionsLen: uint64(len(instructions)),
		calldataLen:     uint64(len(calldata)),
		bodyLen:         uint64(len(body)),
	}

	// write header
	buf := h.toBytes()
	buf = append(buf, levels...)
	buf = append(buf, instructions...)
	buf = append(buf, calldata...)
	buf = append(buf, body...)

	return buf, nil
}

func (cs *System) FromBytes(data []byte) (int, error) {
	if len(data) < headerLen {
		return 0, errors.New("invalid data length")
	}
	h := new(header)
	h.fromBytes(data)

	// read the binary-friendly part of the system
	// * the packed instructions
	// * the calldata
	// * the levels
	if len(data) < headerLen+int(h.levelsLen)+int(h.instructionsLen)+int(h.calldataLen)+int(h.bodyLen) {
		return 0, errors.New("invalid data length")
	}

	var g errgroup.Group

	g.Go(func() error {
		return cs.levelsFromBytes(data[headerLen : headerLen+h.levelsLen])
	})

	g.Go(func() error {
		return cs.instructionsFromBytes(data[headerLen+h.levelsLen : headerLen+h.levelsLen+h.instructionsLen])
	})

	g.Go(func() error {
		return cs.calldataFromBytes(data[headerLen+h.levelsLen+h.instructionsLen : headerLen+h.levelsLen+h.instructionsLen+h.calldataLen])
	})

	// CBOR decoding of the constraint system (except what we do directly in binary)
	ts := getTagSet()
	dm, err := cbor.DecOptions{
		MaxArrayElements: 2147483647,
		MaxMapPairs:      2147483647,
	}.DecModeWithTags(ts)

	if err != nil {
		return 0, err
	}
	decoder := dm.NewDecoder(bytes.NewReader(data[headerLen+h.levelsLen+h.instructionsLen+h.calldataLen : headerLen+h.levelsLen+h.instructionsLen+h.calldataLen+h.bodyLen]))

	if err := decoder.Decode(&cs); err != nil {
		return 0, err
	}

	if err := cs.CheckSerializationHeader(); err != nil {
		return 0, err
	}

	switch v := cs.CommitmentInfo.(type) {
	case *Groth16Commitments:
		cs.CommitmentInfo = *v
	case *PlonkCommitments:
		cs.CommitmentInfo = *v
	}

	if err := g.Wait(); err != nil {
		return 0, err
	}

	return headerLen + int(h.levelsLen) + int(h.instructionsLen) + int(h.calldataLen) + int(h.bodyLen), nil
}

func (cs *System) toBytes() ([]byte, error) {
	// CBOR encoding of the constraint system (except what we do directly in binary)
	ts := getTagSet()
	enc, err := cbor.CoreDetEncOptions().EncModeWithTags(ts)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	encoder := enc.NewEncoder(buf)

	// encode our object
	err = encoder.Encode(cs)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

const headerLen = 4 * 8

type header struct {
	// length in bytes of each sections
	levelsLen       uint64
	instructionsLen uint64
	calldataLen     uint64
	bodyLen         uint64
}

func (h *header) toBytes() []byte {
	buf := make([]byte, 0, 8*4+h.levelsLen+h.instructionsLen+h.calldataLen+h.bodyLen)

	buf = binary.LittleEndian.AppendUint64(buf, h.levelsLen)
	buf = binary.LittleEndian.AppendUint64(buf, h.instructionsLen)
	buf = binary.LittleEndian.AppendUint64(buf, h.calldataLen)
	buf = binary.LittleEndian.AppendUint64(buf, h.bodyLen)

	fmt.Printf("calldataLen: %d\n", h.calldataLen/1024/1024)

	return buf
}

func (h *header) fromBytes(buf []byte) {
	h.levelsLen = binary.LittleEndian.Uint64(buf[:8])
	h.instructionsLen = binary.LittleEndian.Uint64(buf[8:16])
	h.calldataLen = binary.LittleEndian.Uint64(buf[16:24])
	h.bodyLen = binary.LittleEndian.Uint64(buf[24:32])
}

func (cs *System) calldataToBytes() []byte {
	buf := make([]byte, 0, 8+len(cs.CallData)*binary.MaxVarintLen64)

	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(cs.CallData)))
	for _, v := range cs.CallData {
		buf = binary.AppendUvarint(buf, uint64(v))
	}

	return buf
}

func (cs *System) instructionsToBytes() ([]byte, error) {
	// prepare the []uint32 separated slices for the packed instructions
	sBlueprintID := make([]uint32, len(cs.Instructions))
	sConstraintOffset := make([]uint32, len(cs.Instructions))
	sWireOffset := make([]uint32, len(cs.Instructions))
	sStartCallData := make([]uint64, len(cs.Instructions))

	// collect them
	for i, inst := range cs.Instructions {
		sBlueprintID[i] = uint32(inst.BlueprintID)
		sConstraintOffset[i] = inst.ConstraintOffset
		sWireOffset[i] = inst.WireOffset
		sStartCallData[i] = inst.StartCallData
	}

	// they compress very well due to their nature (sequential integers)
	var buf32 []uint32
	var err error
	var buf bytes.Buffer
	buf.Grow(4 * len(cs.Instructions) * 3)

	buf32, err = ioutils.CompressAndWriteUints32(&buf, sBlueprintID, buf32)
	if err != nil {
		return nil, err
	}
	buf32, err = ioutils.CompressAndWriteUints32(&buf, sConstraintOffset, buf32)
	if err != nil {
		return nil, err
	}
	_, err = ioutils.CompressAndWriteUints32(&buf, sWireOffset, buf32)
	if err != nil {
		return nil, err
	}

	err = ioutils.CompressAndWriteUints64(&buf, sStartCallData)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (cs *System) levelsToBytes() ([]byte, error) {
	// they compress very well due to their nature (sequential integers)
	var buf32 []uint32
	var buf bytes.Buffer
	var err error
	buf.Grow(4 * len(cs.Instructions))

	binary.Write(&buf, binary.LittleEndian, uint64(len(cs.Levels)))
	for _, l := range cs.Levels {
		buf32, err = ioutils.CompressAndWriteUints32(&buf, l, buf32)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (cs *System) levelsFromBytes(buf []byte) error {
	r := bytes.NewReader(buf)

	var levelsLen uint64
	if err := binary.Read(r, binary.LittleEndian, &levelsLen); err != nil {
		return err
	}

	cs.Levels = make([][]uint32, levelsLen)
	for i := range cs.Levels {
		n, l, err := ioutils.ReadAndDecompressUints32(r)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("invalid data")
		}
		cs.Levels[i] = l
	}

	return nil
}

func (cs *System) instructionsFromBytes(buf []byte) error {
	r := bytes.NewReader(buf)

	// read the packed instructions
	var sBlueprintID, sConstraintOffset, sWireOffset []uint32
	var sStartCallData []uint64
	var err error
	_, sBlueprintID, err = ioutils.ReadAndDecompressUints32(r)
	if err != nil {
		return err
	}
	_, sConstraintOffset, err = ioutils.ReadAndDecompressUints32(r)
	if err != nil {
		return err
	}
	_, sWireOffset, err = ioutils.ReadAndDecompressUints32(r)
	if err != nil {
		return err
	}
	_, sStartCallData, err = ioutils.ReadAndDecompressUints64(r)
	if err != nil {
		return err
	}

	// rebuild the instructions
	cs.Instructions = make([]PackedInstruction, len(sBlueprintID))
	for i := range cs.Instructions {
		cs.Instructions[i] = PackedInstruction{
			BlueprintID:      BlueprintID(sBlueprintID[i]),
			ConstraintOffset: sConstraintOffset[i],
			WireOffset:       sWireOffset[i],
			StartCallData:    sStartCallData[i],
		}
	}

	return nil
}

func (cs *System) calldataFromBytes(buf []byte) error {

	calldataLen := binary.LittleEndian.Uint64(buf[:8])
	cs.CallData = make([]uint32, calldataLen)

	invalid := false
	offset := 8
	for i := range cs.CallData {
		v, n := binary.Uvarint(buf[offset:])
		if n <= 0 {
			invalid = true
		}
		offset += n
		cs.CallData[i] = uint32(v)
	}

	if invalid {
		return errors.New("invalid data")
	}

	return nil
}

func getTagSet() cbor.TagSet {
	// temporary for refactor
	ts := cbor.NewTagSet()
	// https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
	// 65536-15309735 Unassigned
	tagNum := uint64(5309735)
	addType := func(t reflect.Type) {
		if err := ts.Add(
			cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
			t,
			tagNum,
		); err != nil {
			panic(err)
		}
		tagNum++
	}

	addType(reflect.TypeOf(BlueprintGenericHint{}))
	addType(reflect.TypeOf(BlueprintGenericR1C{}))
	addType(reflect.TypeOf(BlueprintGenericSparseR1C{}))
	addType(reflect.TypeOf(BlueprintSparseR1CAdd{}))
	addType(reflect.TypeOf(BlueprintSparseR1CMul{}))
	addType(reflect.TypeOf(BlueprintSparseR1CBool{}))
	addType(reflect.TypeOf(BlueprintLookupHint{}))
	addType(reflect.TypeOf(Groth16Commitments{}))
	addType(reflect.TypeOf(PlonkCommitments{}))

	return ts
}
