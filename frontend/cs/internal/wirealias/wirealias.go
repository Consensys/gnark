// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package wirealias

// Set tracks plain wire aliases for builder-owned internal wires.
type Set struct {
	parent   []int
	internal []bool
	noAlias  []bool
	aliased  bool
}

func (s *Set) ensure(vid int) {
	for len(s.parent) <= vid {
		i := len(s.parent)
		s.parent = append(s.parent, i)
		s.internal = append(s.internal, false)
		s.noAlias = append(s.noAlias, false)
	}
}

func (s *Set) find(vid int) int {
	s.ensure(vid)
	if s.parent[vid] != vid {
		s.parent[vid] = s.find(s.parent[vid])
	}
	return s.parent[vid]
}

// MarkInternal marks a wire as builder-owned and eligible for aliasing unless
// it later escapes to a subsystem that stores raw wire IDs.
func (s *Set) MarkInternal(vid int) {
	s.ensure(vid)
	s.internal[vid] = true
}

// MarkNoAlias excludes the wire's current alias class from future equality
// elimination. Existing aliases are preserved; callers that mark an already
// aliased wire must first canonicalize the escaped reference through Rep.
func (s *Set) MarkNoAlias(vid int) {
	root := s.find(vid)
	s.noAlias[vid] = true
	s.noAlias[root] = true
}

// Union records x == y and prefers the lower wire ID as deterministic
// representative for internal-only aliases. The method returns false when the
// equality is unsafe to optimize and must remain an explicit constraint.
func (s *Set) Union(x, y int) bool {
	if x == y {
		return false
	}
	rx, ry := s.find(x), s.find(y)
	if rx == ry {
		return true
	}

	if s.canEliminateRoot(rx) && s.canEliminateRoot(ry) {
		if ry < rx {
			rx, ry = ry, rx
		}
		s.parent[ry] = rx
		s.aliased = true
		return true
	}

	return false
}

func (s *Set) canEliminateRoot(root int) bool {
	return s.internal[root] && !s.noAlias[root]
}

// Rep returns the current representative for vid.
func (s *Set) Rep(vid int) int {
	return s.find(vid)
}

// HasAliases reports whether at least one non-trivial union was recorded.
func (s *Set) HasAliases() bool {
	return s.aliased
}

// Mappings returns eliminated wire IDs paired with their representative.
func (s *Set) Mappings() [][2]int {
	if !s.aliased {
		return nil
	}
	res := make([][2]int, 0)
	for vid := range s.parent {
		root := s.find(vid)
		if root != vid {
			res = append(res, [2]int{vid, root})
		}
	}
	return res
}
