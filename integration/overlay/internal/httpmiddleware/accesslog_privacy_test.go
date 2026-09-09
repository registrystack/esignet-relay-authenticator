package httpmiddleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type AccessLogPrivacySuite struct{ suite.Suite }

func TestAccessLogPrivacySuite(t *testing.T) {
	if os.Getenv("ESIGNET_ACCESS_LOG_TEST_CHILD") == "1" {
		request := httptest.NewRequest(http.MethodGet, "/authorize?state=private-query-state&access_token=private-token", nil)
		request.Header.Set("Referer", "https://rp.example.test/callback?code=private-callback-code")
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("state") != "private-query-state" ||
				r.URL.Query().Get("access_token") != "private-token" ||
				!strings.Contains(r.Referer(), "private-callback-code") {
				t.Error("access logging changed the request received by the handler")
			}
			w.WriteHeader(http.StatusNoContent)
		})
		AccessLog(next).ServeHTTP(httptest.NewRecorder(), request)
		return
	}
	suite.Run(t, new(AccessLogPrivacySuite))
}

func (s *AccessLogPrivacySuite) TestQueryAndRefererNeverEnterAccessLog() {
	// The host logger binds stdout once. A child test process isolates that
	// singleton and captures real emitted JSON without changing production code.
	command := exec.Command(os.Args[0], "-test.run=^TestAccessLogPrivacySuite$")
	command.Env = append(os.Environ(), "ESIGNET_ACCESS_LOG_TEST_CHILD=1")
	output, err := command.CombinedOutput()
	s.Require().NoError(err, string(output))
	s.NotContains(string(output), "private-query-state")
	s.NotContains(string(output), "private-token")
	s.NotContains(string(output), "private-callback-code")
	s.NotContains(string(output), "req.referer")
	var record map[string]any
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "{") {
			s.Require().NoError(json.Unmarshal([]byte(line), &record))
			break
		}
	}
	s.Require().NotNil(record)
	s.Equal("/authorize", record["req.requestURI"])
	s.Equal(float64(http.StatusNoContent), record["statusCode"])
}
