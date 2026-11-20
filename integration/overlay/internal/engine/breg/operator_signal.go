package breg

import (
	"context"

	applog "github.com/mosip/esignet/internal/log"
	core "github.com/registrystack/esignet-relay-authenticator/provider"
)

// operatorLines gives each operator event one fixed log line. An event carries
// only its kind, so a line never holds an identifier, contact, code or
// Messaging response.
var operatorLines = map[core.OperatorEvent]string{
	core.EventSendRefused: "Registry Messaging refused a sign-in code, so none was sent",
	core.EventSendFailed:  "A sign-in code could not be handed to Registry Messaging and may not have been sent",
	core.EventSendDropped: "Too many sign-in code sends were in flight, so one was not sent",
	core.EventLimiterFull: "The sign-in limiter is full, so sign-in codes are being refused",
	core.EventStoreFull:   "The pending sign-in code store is full, so sign-in codes are being refused",
}

// operatorSignal writes one host log line per event, at warning level. It does
// no network or lock work, so it is safe to call from a request or a send.
func operatorSignal(logger *applog.Logger) func(core.OperatorEvent) {
	return func(e core.OperatorEvent) {
		line, ok := operatorLines[e]
		if !ok {
			line = "Unrecognised sign-in code event"
		}
		logger.Warn(context.Background(), line, applog.String("event", string(e)))
	}
}
