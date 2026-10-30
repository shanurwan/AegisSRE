package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The demo replays demo/data/scenarios.json. If the security code changes
// what an attack produces, this fails until the file is regenerated, so the
// demo can never show an outcome the code no longer produces.
func TestScenariosMatchCommittedData(t *testing.T) {
	data, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range data.Scenarios {
		if scenario.ID != "legitimate" && !scenario.Blocked {
			t.Errorf("attack %q was not blocked: %+v", scenario.ID, scenario)
		}
	}
	generated, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join("..", "..", "demo", "data", "scenarios.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout may hold the file with CRLF line endings.
	committed = bytes.ReplaceAll(committed, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(bytes.TrimSpace(committed), bytes.TrimSpace(generated)) {
		t.Fatal("demo/data/scenarios.json is stale; run: go run ./hack/breach demo/data/scenarios.json")
	}
}
