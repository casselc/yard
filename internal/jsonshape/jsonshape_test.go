package jsonshape

import (
	"encoding/json"
	"strings"
	"testing"

	"hegel.dev/go/hegel"
)

const review = `{"type":"object","additionalProperties":false,"required":["verdict","findings"],"properties":{
 "verdict":{"type":"string","enum":["pass","fail","insufficient_information"]},
 "findings":{"type":"array","maxItems":50,"items":{"type":"object","additionalProperties":false,
   "required":["file","line","severity","note"],"properties":{
   "file":{"type":"string","maxLength":200},"line":{"type":"integer","minimum":1},
   "severity":{"type":"string","enum":["info","minor","major","critical"]},"note":{"type":"string","maxLength":2000}}}},
 "questions":{"type":"array","items":{"type":"string"}}}}`

func TestValidReviewsPassAndBrokenOnesFail(t *testing.T) {
	s, err := Parse([]byte(review))
	if err != nil {
		t.Fatal(err)
	}
	hegel.Test(t, func(ht *hegel.T) {
		n := hegel.Draw(ht, hegel.Integers(0, 5))
		fs := []map[string]any{}
		for i := 0; i < n; i++ {
			fs = append(fs, map[string]any{
				"file":     hegel.Draw(ht, hegel.Text().MaxSize(50)),
				"line":     hegel.Draw(ht, hegel.Integers(1, 100000)),
				"severity": []string{"info", "minor", "major", "critical"}[hegel.Draw(ht, hegel.Integers(0, 3))],
				"note":     hegel.Draw(ht, hegel.Text().MaxSize(100)),
			})
		}
		doc := map[string]any{"verdict": []string{"pass", "fail", "insufficient_information"}[hegel.Draw(ht, hegel.Integers(0, 2))],
			"findings": fs}
		raw, _ := json.Marshal(doc)
		if errs := s.Validate(raw); len(errs) > 0 {
			ht.Fatalf("valid review refused: %v\n%s", errs, raw)
		}
		// one structural break, chosen by the engine, must be reported
		var broken any = doc
		switch hegel.Draw(ht, hegel.Integers(0, 5)) {
		case 0:
			delete(doc, "verdict")
		case 1:
			doc["verdict"] = "maybe"
		case 2:
			doc["extra"] = true
		case 3:
			doc["findings"] = map[string]any{}
		case 4:
			if n == 0 {
				ht.Assume(false)
			}
			fs[0]["line"] = 0
		case 5:
			broken = []any{doc}
		}
		raw, _ = json.Marshal(broken)
		if errs := s.Validate(raw); len(errs) == 0 {
			ht.Fatalf("broken review accepted:\n%s", raw)
		}
	})
}

func TestEdges(t *testing.T) {
	s, _ := Parse([]byte(review))
	for _, c := range []struct {
		doc string
		ok  bool
	}{
		{`{"verdict":"pass","findings":[]}`, true},
		{`{"verdict":"pass","findings":[]} {}`, false},                                                 // trailing data
		{`{"verdict":"pass","findings":[{"file":"a","line":1.5,"severity":"info","note":""}]}`, false}, // not an integer
		{`{"verdict":1,"findings":[]}`, false},
		{`not json`, false},
	} {
		if errs := s.Validate([]byte(c.doc)); (len(errs) == 0) != c.ok {
			t.Errorf("%s: %v", c.doc, errs)
		}
	}
	if _, err := Parse([]byte(`{"type":"object","oneOf":[]}`)); err == nil || !strings.Contains(err.Error(), "oneOf") {
		t.Errorf("unsupported keyword accepted: %v", err)
	}
	str, _ := Parse([]byte(`{"type":"string","enum":["1"]}`))
	if errs := str.Validate([]byte(`1`)); len(errs) == 0 {
		t.Errorf("number 1 matched enum string \"1\"")
	}
}
