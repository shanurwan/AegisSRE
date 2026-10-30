package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/shanurwan/AegisSRE/internal/core/model"
)

type recordingMessenger struct {
	endpoint string
	err      error
}

func (r *recordingMessenger) Send(_ context.Context, endpoint string, _ model.Envelope, _ any) error {
	r.endpoint = endpoint
	return r.err
}

type countingResolver struct {
	Static
	forgotten []model.AgentID
}

func (c *countingResolver) Forget(agent model.AgentID) { c.forgotten = append(c.forgotten, agent) }

func TestMessengerSendsToTheResolvedEndpoint(t *testing.T) {
	next := &recordingMessenger{}
	messenger := Messenger{Resolver: Static{model.AgentInvestigator: "https://investigator.example"}, Next: next}
	envelope := model.Envelope{Recipient: model.AgentInvestigator}
	if err := messenger.Send(context.Background(), "https://ignored.example", envelope, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	if next.endpoint != "https://investigator.example" {
		t.Fatalf("sent to %q", next.endpoint)
	}
}

func TestMessengerFailsClosedWithoutAnEndpoint(t *testing.T) {
	next := &recordingMessenger{}
	messenger := Messenger{Resolver: Static{}, Next: next}
	err := messenger.Send(context.Background(), "https://ignored.example", model.Envelope{Recipient: model.AgentOperator}, &struct{}{})
	if code, _ := model.ErrorCodeOf(err); code != model.CodeOutOfScope {
		t.Fatalf("error = %v, want OUT_OF_SCOPE", err)
	}
	if next.endpoint != "" {
		t.Fatal("message was sent without a resolved endpoint")
	}
}

func TestMessengerForgetsAPeerThatFails(t *testing.T) {
	resolver := &countingResolver{Static: Static{model.AgentOperator: "https://operator.example"}}
	next := &recordingMessenger{err: errors.New("connection refused")}
	messenger := Messenger{Resolver: resolver, Next: next}
	if err := messenger.Send(context.Background(), "", model.Envelope{Recipient: model.AgentOperator}, &struct{}{}); err == nil {
		t.Fatal("expected the send error")
	}
	if len(resolver.forgotten) != 1 || resolver.forgotten[0] != model.AgentOperator {
		t.Fatalf("forgotten = %v", resolver.forgotten)
	}
}
