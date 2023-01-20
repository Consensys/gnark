package schema

import (
	"container/list"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/consensys/gnark/frontend/schema/internal/reflectwalk"
)

type walker struct {
	handler            LeafHandlerNEW
	target             reflect.Type
	targetSlice        reflect.Type
	path               *list.List
	nbPublic, nbSecret int
}

type LeafInfo struct {
	Visibility Visibility
	FullName   func() string
	name       string
}

type LeafCount struct {
	NbSecret int // TODO @gbotrel rename to Secret
	NbPublic int
}

func Walk(circuit interface{}, tLeaf reflect.Type, handler LeafHandlerNEW) (count LeafCount, err error) {
	w := walker{
		target:      tLeaf,
		targetSlice: reflect.SliceOf(tLeaf),
		handler:     handler,
		path:        list.New(),
	}
	err = reflectwalk.Walk(circuit, &w)
	if err == reflectwalk.SkipEntry {
		err = nil
	}
	count.NbPublic = w.nbPublic
	count.NbSecret = w.nbSecret
	return
}

func (w *walker) Interface(value reflect.Value) error {
	if value.Type() != w.target {
		return nil
	}
	v := w.visibility()
	if v == Unset {
		v = Secret
	}

	// call the handler.
	if w.handler != nil {
		if err := w.handler(LeafInfo{Visibility: v, FullName: w.name, name: ""}, value); err != nil {
			return err
		}
	}

	if v == Secret {
		w.nbSecret++
	} else if v == Public {
		w.nbPublic++
	}
	return nil
}

func (w *walker) Slice(value reflect.Value) error {
	if value.Type() == w.targetSlice {
		if value.Len() == 0 {
			fmt.Printf("ignoring uninitizalized slice: %s %s\n", w.name(), reflect.SliceOf(w.target).String())
			return nil
		}
		return w.handleLeaves(value)
	}

	return nil
}
func (w *walker) SliceElem(index int, _ reflect.Value) error {
	w.path.PushBack(LeafInfo{Visibility: w.visibility(), name: strconv.Itoa(index)})
	return nil
}

func (w *walker) Array(value reflect.Value) error {
	if value.Type() == reflect.ArrayOf(value.Len(), w.target) {
		return w.handleLeaves(value)
	}
	return nil
}
func (w *walker) ArrayElem(index int, _ reflect.Value) error {
	w.path.PushBack(LeafInfo{Visibility: w.visibility(), name: strconv.Itoa(index)})
	return nil
}

// process an array or slice of leaves; since it's quite common to have large array/slices
// of frontend.Variable, this speeds up considerably performance.
func (w *walker) handleLeaves(value reflect.Value) error {
	// TODO @gbotrel restore
	return nil
	v := w.visibility()
	if v == Unset {
		v = Secret
	}

	// call the handler.
	if w.handler != nil {
		n := w.name()
		currI := 0
		fName := func() string {
			return n + "_" + strconv.Itoa(currI)
		}
		for i := 0; i < value.Len(); i++ {
			currI = i
			if err := w.handler(LeafInfo{Visibility: v, FullName: fName, name: ""}, value.Index(i)); err != nil {
				return err
			}
		}
	}

	if v == Secret {
		w.nbSecret += value.Len()
	} else if v == Public {
		w.nbPublic += value.Len()
	}
	return reflectwalk.SkipEntry
}

func (w *walker) Struct(reflect.Value) error {
	return nil
}

func (w *walker) StructField(sf reflect.StructField, v reflect.Value) error {
	// check if the gnark tag is set
	tag, ok := sf.Tag.Lookup(string(tagKey))
	if ok && tag == string(TagOptOmit) {
		return reflectwalk.SkipEntry // skipping "-"
	}

	// default visibility: parent (or unset)
	parentVisibility := w.visibility()
	var nameInTag string
	m := LeafInfo{
		name:       sf.Name,
		Visibility: parentVisibility,
	}

	if ok && tag != "" {
		// gnark tag is set
		var opts tagOptions
		nameInTag, opts = parseTag(tag)
		if !isValidTag(nameInTag) {
			nameInTag = ""
		}
		if nameInTag != "" {
			m.name = nameInTag // TODO @gbotrel when building a schema we need to keep the name to instantiate a valid struct.
		}
		opts = tagOptions(strings.TrimSpace(string(opts)))
		switch {
		case opts.contains(TagOptSecret):
			m.Visibility = Secret
		case opts.contains(TagOptPublic):
			m.Visibility = Public
		}
	}

	if parentVisibility != Unset && parentVisibility != m.Visibility {
		return fmt.Errorf("conflicting visibility. %s (%s) has a parent with different visibility attribute", m.name, m.Visibility.String()) // TODO full name
	}

	w.path.PushBack(m)

	return nil
}

func (w *walker) Enter(l reflectwalk.Location) error {
	return nil
}

func (w *walker) Exit(l reflectwalk.Location) error {
	if l == reflectwalk.StructField || l == reflectwalk.ArrayElem || l == reflectwalk.SliceElem {
		w.path.Remove(w.path.Back())
	}
	return nil
}

// defaults to unset
func (w *walker) visibility() Visibility {
	if w.path.Len() > 0 {
		return w.path.Back().Value.(LeafInfo).Visibility
	}
	return Unset
}

func (w *walker) name() string {
	if w.path.Len() == 0 {
		return ""
	}
	var sbb strings.Builder
	sbb.Grow(w.path.Len() * 10)
	first := true
	for e := w.path.Front(); e != nil; e = e.Next() {
		if !first {
			sbb.WriteByte('_')
		} else {
			first = false
		}
		m := e.Value.(LeafInfo)
		sbb.WriteString(m.name)
	}
	return sbb.String()
}
