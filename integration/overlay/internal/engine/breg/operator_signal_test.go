package breg

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	applog "github.com/mosip/esignet/internal/log"
	core "github.com/registrystack/esignet-relay-authenticator/provider"
)

// Each operator event becomes one host log line that names the event kind and
// nothing else.
func TestOperatorSignalLogsOneLinePerEvent(t *testing.T) {
	if os.Getenv("RELAY_OPERATOR_SIGNAL_TEST_CHILD") == "1" {
		signal := operatorSignal(applog.GetLogger())
		signal(core.EventSendRefused)
		signal(core.EventLimiterFull)
		return
	}
	// The host logger binds stdout once, so a child test process captures the
	// JSON it really writes.
	command := exec.Command(os.Args[0], "-test.run=^TestOperatorSignalLogsOneLinePerEvent$")
	command.Env = append(os.Environ(), "RELAY_OPERATOR_SIGNAL_TEST_CHILD=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, output)
	}
	var records []map[string]any
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "{") {
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatal(err)
			}
			records = append(records, record)
		}
	}
	if len(records) != 2 {
		t.Fatalf("want one line per event, got %d: %s", len(records), output)
	}
	for i, kind := range []core.OperatorEvent{core.EventSendRefused, core.EventLimiterFull} {
		if records[i]["event"] != string(kind) || records[i]["message"] != operatorLines[kind] {
			t.Errorf("line %d does not name %s: %v", i, kind, records[i])
		}
		for key := range records[i] {
			switch key {
			case "@timestamp", "@version", "appName", "event", "level", "level_value", "message", "traceId":
			default:
				t.Errorf("line %d carries an unexpected field %q", i, key)
			}
		}
	}
}

func TestEveryOperatorEventHasAFixedLine(t *testing.T) {
	for _, e := range []core.OperatorEvent{core.EventSendRefused, core.EventSendFailed, core.EventSendDropped, core.EventLimiterFull, core.EventStoreFull} {
		if operatorLines[e] == "" {
			t.Errorf("no log line for %s", e)
		}
	}
}
