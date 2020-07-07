package frontend

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/consensys/gnark/encoding/gob"
)

type Circuit interface {
	// Circuit describes the circuit's constraints
	Circuit(ctx *Context, cs *CS) error
}

type CircuitWithInitHook interface {
	// Init is a post-init hook to perform non-standard initializations
	// for example, we may need to set some aliases between inputs
	PostInit(ctx *Context) error
}

func Compile(ctx *Context, circuit Circuit) (*R1CS, error) {
	// instantiate our constraint system
	cs := New()

	// recursively parse through reflection the circuits members to find all constraints that need to be allocated
	// (secret or public inputs)
	if err := parseType(&cs, circuit, "", unset); err != nil {
		return nil, err
	}

	// call post-init hook, if implemented
	t := reflect.TypeOf((*CircuitWithInitHook)(nil)).Elem()
	if reflect.TypeOf(circuit).Implements(t) {
		// TODO that's a bit risky / user un-friendly as we don't actually check that at compile time.
		// ex: user could have a typo on his PostInit() hook method and never know it's not called.
		if err := circuit.(CircuitWithInitHook).PostInit(ctx); err != nil {
			return nil, err
		}
	}

	// TODO lock input variables allocations to forbid user to call circuit.SECRET_INPUT() inside the Circuit() method

	// call Circuit() to fill in the constraints
	if err := circuit.Circuit(ctx, &cs); err != nil {
		return nil, err
	}

	// return R1CS
	return cs.ToR1CS(), nil
}

func Save(ctx *Context, r1cs *R1CS, path string) error {
	return gob.Write(path, r1cs, ctx.CurveID())
}

// -------------------------------------------------------------------------------------------------
// Util method to parse and allocate circuit's inputs

const tagKey = "gnark"
const maxTags = 2
const attrPublic = "public"
const attrSecret = "secret"

type attrVisibility uint8

const (
	unset attrVisibility = iota
	secret
	public
)

var errInvalidTag = errors.New("invalid tag format")

func getAttrVisibility(tagValues []string) (newValues []string, visibility attrVisibility) {
	visibility = unset
	for i := 0; i < len(tagValues); i++ {
		tag := strings.TrimSpace(tagValues[i])
		if tag == attrPublic {
			if visibility != unset {
				panic("multiple visibility tag values in struct")
			}
			visibility = public
		} else if tag == attrSecret {
			if visibility != unset {
				panic("multiple visibility tag values in struct")
			}
			visibility = secret
		} else {
			newValues = append(newValues, tag)
		}
	}

	if visibility == unset {
		visibility = secret // default visibility to secret
	}
	return
}

func parseType(circuit *CS, input interface{}, baseName string, parentVisibility attrVisibility) error {
	var c *Constraint
	tConstraintBad := reflect.TypeOf(Constraint{})
	tConstraintGood := reflect.TypeOf(c)

	var r *CS
	tCSGood := reflect.TypeOf(CS{})
	tCSBad := reflect.TypeOf(r)

	// pointer to struct
	tValue := reflect.ValueOf(input)
	tInput := tValue.Elem()

	// we either have a pointer, a struct, or a slice / array
	// and recursively parse members / elements until we find a constraint to allocate in the circuit.
	switch tInput.Kind() {
	case reflect.Struct:
		if tInput.Type() == tCSGood {
			return nil
		}
		for i := 0; i < tInput.NumField(); i++ {
			field := tInput.Type().Field((i))

			// get gnark tag
			tagValue := field.Tag.Get(tagKey)
			var tagValues []string
			localVisibility := secret
			attrName := field.Name
			if tagValue != "" {
				// gnark tag is set
				tagValues = strings.Split(tagValue, ",")
				if len(tagValues) > 2 {
					return errInvalidTag
				}
				tagValues, localVisibility = getAttrVisibility(tagValues)
				if len(tagValues) == 1 {
					attrName = tagValues[0]
				}
			}
			if parentVisibility != unset {
				localVisibility = parentVisibility // parent visibility overhides
			}

			inputName := appendName(baseName, attrName)

			f := tInput.FieldByName(field.Name)
			if f.CanAddr() && f.Addr().CanInterface() {
				val := f.Addr().Interface()
				if err := parseType(circuit, val, inputName, localVisibility); err != nil {
					return err
				}
			}
		}

	case reflect.Ptr:
		switch tInput.Type() {
		case tCSBad:
			return errors.New("circuit should embbed *CS, not CS")
		case tConstraintBad:
			return errors.New("circuit has a Constraint member -- use only *Constraint (field name: " + baseName + " )")
		case tConstraintGood:
			// *Constraint --> we need to allocate it

			switch parentVisibility {
			case unset, secret:
				if tInput.CanSet() {
					fmt.Println("allocating secret input", baseName)
					raw := circuit.SECRET_INPUT(baseName)
					// TODO check that there is no duplicate of value here
					tInput.Set(reflect.ValueOf(raw))
				} else {
					return errors.New("can't set val " + baseName)
				}
			case public:
				if tInput.CanSet() {
					fmt.Println("allocating public input", baseName)
					raw := circuit.PUBLIC_INPUT(baseName)
					// TODO check that there is no duplicate of value here
					tInput.Set(reflect.ValueOf(raw))
				} else {
					return errors.New("can't set val " + baseName)
				}
			}
		default:
			return nil // pointer to something we don't care about
		}
	case reflect.Slice, reflect.Array:
		if tInput.Len() == 0 {
			fmt.Println("warning, got unitizalized slice (or empty array). Ignoring;")
			return nil
		}
		for j := 0; j < tInput.Len(); j++ {
			val := tInput.Index(j).Addr().Interface()
			if err := parseType(circuit, val, appendName(baseName, strconv.Itoa(j)), parentVisibility); err != nil {
				return err
			}
		}
	}

	return nil
}

func appendName(baseName, name string) string {
	if baseName == "" {
		return name
	} else {
		return baseName + "_" + name
	}
}
