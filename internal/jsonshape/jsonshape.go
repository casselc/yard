// Package jsonshape validates a JSON value's structure against a small subset of JSON Schema: type (object, array,
// string, integer, number, boolean, null), properties, required, additionalProperties (false), items, enum,
// minimum, maxItems and maxLength. Yard checks structure only (design/AGENT-OPERATIONS.md section 4); whether a
// result satisfies its task is the workflow's decision.
package jsonshape

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

type Schema struct {
	Type                 string             `json:"type"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	AdditionalProperties *bool              `json:"additionalProperties,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	Enum                 []any              `json:"enum,omitempty"`
	Minimum              *float64           `json:"minimum,omitempty"`
	MaxItems             *int               `json:"maxItems,omitempty"`
	MaxLength            *int               `json:"maxLength,omitempty"`
}

// Parse reads a schema, refusing keywords it does not implement (a schema it cannot check is not a check).
func Parse(raw []byte) (*Schema, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s Schema
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("jsonshape: %w", err)
	}
	return &s, nil
}

// Validate decodes raw and checks it, returning every violation (path: message), sorted.
func (s *Schema) Validate(raw []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return []string{"$: not JSON: " + err.Error()}
	}
	if dec.More() {
		return []string{"$: trailing data after the value"}
	}
	var errs []string
	s.check("$", v, &errs)
	sort.Strings(errs)
	return errs
}

func (s *Schema) check(path string, v any, errs *[]string) {
	bad := func(format string, args ...any) { *errs = append(*errs, path+": "+fmt.Sprintf(format, args...)) }
	switch s.Type {
	case "object":
		o, ok := v.(map[string]any)
		if !ok {
			bad("want an object")
			return
		}
		for _, k := range s.Required {
			if _, ok := o[k]; !ok {
				bad("missing %q", k)
			}
		}
		keys := make([]string, 0, len(o))
		for k := range o {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p, ok := s.Properties[k]; ok {
				p.check(path+"."+k, o[k], errs)
			} else if s.AdditionalProperties != nil && !*s.AdditionalProperties {
				bad("unexpected property %q", k)
			}
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			bad("want an array")
			return
		}
		if s.MaxItems != nil && len(a) > *s.MaxItems {
			bad("%d items, at most %d", len(a), *s.MaxItems)
		}
		if s.Items != nil {
			for i, x := range a {
				s.Items.check(fmt.Sprintf("%s[%d]", path, i), x, errs)
			}
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			bad("want a string")
			return
		}
		if s.MaxLength != nil && len([]rune(str)) > *s.MaxLength {
			bad("longer than %d", *s.MaxLength)
		}
	case "integer", "number":
		n, ok := v.(json.Number)
		if !ok {
			bad("want a %s", s.Type)
			return
		}
		f, err := n.Float64()
		if err != nil || math.IsInf(f, 0) {
			bad("not a finite number")
			return
		}
		if s.Type == "integer" {
			if _, err := n.Int64(); err != nil {
				bad("want an integer")
				return
			}
		}
		if s.Minimum != nil && f < *s.Minimum {
			bad("below the minimum %v", *s.Minimum)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			bad("want a boolean")
		}
	case "null":
		if v != nil {
			bad("want null")
		}
	case "":
	default:
		bad("schema type %q is not supported", s.Type)
	}
	if len(s.Enum) > 0 {
		vj, _ := json.Marshal(v)
		for _, e := range s.Enum {
			if ej, _ := json.Marshal(e); bytes.Equal(ej, vj) { // type-aware: "1" is not 1
				return
			}
		}
		bad("not one of %v", s.Enum)
	}
}
