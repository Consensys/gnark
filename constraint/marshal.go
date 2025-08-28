package constraint

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"

	"github.com/consensys/gnark/internal/backend/ioutils"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sync/errgroup"
)

// ToBytes serializes the constraint system to a byte slice
// This is not meant to be called directly since the constraint.System is embedded in
// a "curve-typed" system (e.g. bls12-381.system)
func (system *System) ToBytes() ([]byte, error) {
	// we prepare and write 4 distinct blocks of data;
	// that allow for a more efficient serialization/deserialization (+ parallelism)
	var calldata, instructions, levels []byte
	var g errgroup.Group
	g.Go(func() error {
		var err error
		calldata, err = system.calldataToBytes()
		return err
	})
	g.Go(func() error {
		var err error
		instructions, err = system.instructionsToBytes()
		return err
	})
	g.Go(func() error {
		var err error
		levels, err = system.levelsToBytes()
		return err
	})
	body, err := system.toBytes()
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

// FromBytes deserializes the constraint system from a byte slice
// This is not meant to be called directly since the constraint.System is embedded in
// a "curve-typed" system (e.g. bls12-381.system)
func (system *System) FromBytes(data []byte) (int, error) {
	if len(data) < headerLen {
		return 0, errors.New("invalid data length")
	}

	// read the header which contains the length of each section
	h := new(header)
	h.fromBytes(data)

	if len(data) < headerLen+int(h.levelsLen)+int(h.instructionsLen)+int(h.calldataLen)+int(h.bodyLen) {
		return 0, errors.New("invalid data length")
	}

	// read the sections in parallel
	var g errgroup.Group
	g.Go(func() error {
		return system.levelsFromBytes(data[headerLen : headerLen+h.levelsLen])
	})

	g.Go(func() error {
		return system.instructionsFromBytes(data[headerLen+h.levelsLen : headerLen+h.levelsLen+h.instructionsLen])
	})

	g.Go(func() error {
		return system.calldataFromBytes(data[headerLen+h.levelsLen+h.instructionsLen : headerLen+h.levelsLen+h.instructionsLen+h.calldataLen])
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

	if err := decoder.Decode(&system); err != nil {
		return 0, err
	}

	if err := system.CheckSerializationHeader(); err != nil {
		return 0, err
	}

	switch v := system.CommitmentInfo.(type) {
	case *Groth16Commitments:
		system.CommitmentInfo = *v
	case *PlonkCommitments:
		system.CommitmentInfo = *v
	}

	if err := g.Wait(); err != nil {
		return 0, err
	}

	return headerLen + int(h.levelsLen) + int(h.instructionsLen) + int(h.calldataLen) + int(h.bodyLen), nil
}

func (system *System) toBytes() ([]byte, error) {
	// CBOR encoding of the constraint system (except what we do directly in binary)
	ts := getTagSet()
	enc, err := cbor.CoreDetEncOptions().EncModeWithTags(ts)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	encoder := enc.NewEncoder(buf)

	// encode our object
	err = encoder.Encode(system)
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

	return buf
}

func (h *header) fromBytes(buf []byte) {
	h.levelsLen = binary.LittleEndian.Uint64(buf[:8])
	h.instructionsLen = binary.LittleEndian.Uint64(buf[8:16])
	h.calldataLen = binary.LittleEndian.Uint64(buf[16:24])
	h.bodyLen = binary.LittleEndian.Uint64(buf[24:32])
}

func (system *System) calldataToBytes() ([]byte, error) {
	// calldata doesn't compress as well as the other sections;
	// it still gives a better size to use intcomp.CompressUint32 here,
	// and an even better one to use binary.UVarint
	// but, we keep it simple as it makes deserialization much faster
	// user is still free to compress the final []byte slice if needed.
	buf := make([]byte, 0, 8+len(system.CallData)*binary.MaxVarintLen32)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(system.CallData)))
	// binary.LittleEndian.PutUint64(buf, uint64(len(system.CallData)))
	// buf = buf[:8+len(system.CallData)*4]
	for _, v := range system.CallData {
		buf = binary.AppendUvarint(buf, uint64(v))
		// binary.LittleEndian.PutUint32(buf[8+i*4:8+i*4+4], v)
	}
	return buf, nil
}

func (system *System) instructionsToBytes() ([]byte, error) {
	// prepare the []uint32 separated slices for the packed instructions
	sBlueprintID := make([]uint32, len(system.Instructions))
	sConstraintOffset := make([]uint32, len(system.Instructions))
	sWireOffset := make([]uint32, len(system.Instructions))
	sStartCallData := make([]uint64, len(system.Instructions))

	// collect them
	for i, inst := range system.Instructions {
		sBlueprintID[i] = uint32(inst.BlueprintID)
		sConstraintOffset[i] = inst.ConstraintOffset
		sWireOffset[i] = inst.WireOffset
		sStartCallData[i] = inst.StartCallData
	}

	// they compress very well due to their nature (sequential integers)
	var buf32 []uint32
	var err error
	var buf bytes.Buffer
	buf.Grow(4 * len(system.Instructions) * 3)

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

func (system *System) levelsToBytes() ([]byte, error) {
	// they compress very well due to their nature (sequential integers)
	var buf32 []uint32
	var buf bytes.Buffer
	var err error
	buf.Grow(4 * len(system.Instructions))

	binary.Write(&buf, binary.LittleEndian, uint64(len(system.Levels)))
	for _, l := range system.Levels {
		buf32, err = ioutils.CompressAndWriteUints32(&buf, l, buf32)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (system *System) levelsFromBytes(in []byte) error {

	levelsLen := binary.LittleEndian.Uint64(in[:8])

	in = in[8:]

	var (
		buf32 []uint32
		err   error
		n     int
	)

	system.Levels = make([][]uint32, levelsLen)
	for i := range system.Levels {
		buf32, n, system.Levels[i], err = ioutils.ReadAndDecompressUints32(in, buf32)
		if err != nil {
			return err
		}
		in = in[n:]
	}

	return nil
}

func (system *System) instructionsFromBytes(in []byte) error {

	// read the packed instructions
	var (
		sBlueprintID, sConstraintOffset, sWireOffset []uint32
		sStartCallData                               []uint64
		err                                          error
		n                                            int
		buf32                                        []uint32
	)
	buf32, n, sBlueprintID, err = ioutils.ReadAndDecompressUints32(in, buf32)
	if err != nil {
		return err
	}
	in = in[n:]
	buf32, n, sConstraintOffset, err = ioutils.ReadAndDecompressUints32(in, buf32)
	if err != nil {
		return err
	}
	in = in[n:]
	_, n, sWireOffset, err = ioutils.ReadAndDecompressUints32(in, buf32)
	if err != nil {
		return err
	}
	in = in[n:]
	_, sStartCallData, err = ioutils.ReadAndDecompressUints64(in)
	if err != nil {
		return err
	}

	// rebuild the instructions
	system.Instructions = make([]PackedInstruction, len(sBlueprintID))
	for i := range system.Instructions {
		system.Instructions[i] = PackedInstruction{
			BlueprintID:      BlueprintID(sBlueprintID[i]),
			ConstraintOffset: sConstraintOffset[i],
			WireOffset:       sWireOffset[i],
			StartCallData:    sStartCallData[i],
		}
	}

	return nil
}

func (system *System) calldataFromBytes(buf []byte) error {
	calldataLen := binary.LittleEndian.Uint64(buf[:8])
	system.CallData = make([]uint32, calldataLen)
	buf = buf[8:]
	for i := uint64(0); i < calldataLen; i++ {
		v, n := binary.Uvarint(buf[:min(len(buf), binary.MaxVarintLen64)])
		if n <= 0 {
			return errors.New("invalid calldata")
		}
		system.CallData[i] = uint32(v)
		buf = buf[n:]
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
	addType(reflect.TypeOf(Groth16Commitments{}))
	addType(reflect.TypeOf(PlonkCommitments{}))

	addType(reflect.TypeOf(BlueprintGenericSparseR1C[U32]{}))
	addType(reflect.TypeOf(BlueprintSparseR1CAdd[U32]{}))
	addType(reflect.TypeOf(BlueprintSparseR1CMul[U32]{}))
	addType(reflect.TypeOf(BlueprintSparseR1CBool[U32]{}))
	addType(reflect.TypeOf(BlueprintLookupHint[U32]{}))

	addType(reflect.TypeOf(BlueprintGenericSparseR1C[U64]{}))
	addType(reflect.TypeOf(BlueprintSparseR1CAdd[U64]{}))
	addType(reflect.TypeOf(BlueprintSparseR1CMul[U64]{}))
	addType(reflect.TypeOf(BlueprintSparseR1CBool[U64]{}))
	addType(reflect.TypeOf(BlueprintLookupHint[U64]{}))

	return ts
}
