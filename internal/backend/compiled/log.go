// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compiled

import (
	"strings"
)

// LogEntry is used as a shared data structure between the frontend and the backend
// to represent string values (in logs or debug info) where a value is not known at compile time
// (which is the case for variables that need to be resolved in the R1CS)
type LogEntry struct {
	Format    string
	ToResolve []Term
}

func (l *LogEntry) WriteVariable(le Variable, sbb *strings.Builder) {
	sbb.Grow(len(le.LinExp) * len(" + (xx + xxxxxxxxxxxx"))

	for i := 0; i < len(le.LinExp); i++ {
		if i > 0 {
			sbb.WriteString(" + ")
		}
		l.WriteTerm(le.LinExp[i], sbb)
	}
}

func (l *LogEntry) WriteTerm(t Term, sbb *strings.Builder) {
	// virtual == only a coeff, we discard the wire
	if t.VariableVisibility() == Public && t.WireID() == 0 {
		sbb.WriteString("%s")
		t.SetVariableVisibility(Virtual)
		l.ToResolve = append(l.ToResolve, t)
		return
	}

	cID := t.CoeffID()
	if cID == CoeffIdMinusOne {
		sbb.WriteString("-%s")
	} else if cID == CoeffIdOne {
		sbb.WriteString("%s")
	} else {
		sbb.WriteString("%s*%s")
	}

	l.ToResolve = append(l.ToResolve, t)
}
