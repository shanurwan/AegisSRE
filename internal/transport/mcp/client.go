package mcptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/platform/httpclient"
	"github.com/shanurwan/AegisSRE/internal/platform/observability"
)

type Client struct {
	session *mcp.ClientSession
}

func Connect(ctx context.Context, endpoint, name string, timeout time.Duration) (*Client, error) {
	return ConnectWithHTTPClient(ctx, endpoint, name, timeout, nil)
}

// ConnectWithHTTPClient permits the process composition root to inject an
// mTLS client bound to the exact destination workload identity.
func ConnectWithHTTPClient(ctx context.Context, endpoint, name string, timeout time.Duration, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		httpClient = observability.HTTPClient(httpclient.Direct(timeout))
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           httpClient,
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
		MaxEventSize:         2 << 20,
	}
	client := mcp.NewClient(&mcp.Implementation{Name: name, Version: "v0.1.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect MCP endpoint %s: %w", endpoint, err)
	}
	return &Client{session: session}, nil
}

func (c *Client) Discover(ctx context.Context) ([]string, error) {
	if c == nil || c.session == nil {
		return nil, errors.New("MCP session is unavailable")
	}
	var names []string
	cursor := ""
	for {
		result, err := c.session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("list MCP tools: %w", err)
		}
		for _, tool := range result.Tools {
			if tool != nil {
				names = append(names, tool.Name)
			}
		}
		if result.NextCursor == "" {
			break
		}
		cursor = result.NextCursor
	}
	sort.Strings(names)
	return names, nil
}

func (c *Client) Call(ctx context.Context, name string, input, output any) error {
	if c == nil || c.session == nil {
		return errors.New("MCP session is unavailable")
	}
	result, err := c.session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: input})
	if err != nil {
		return fmt.Errorf("call MCP tool %s: %w", name, err)
	}
	if result.IsError {
		failure := toolFailure{
			SchemaVersion: toolErrorSchemaV1,
			Code:          model.CodeExecutionFailed,
			Message:       "constrained MCP tool failed",
		}
		for _, content := range result.Content {
			if text, ok := content.(*mcp.TextContent); ok && text.Text != "" {
				var candidate toolFailure
				decoder := json.NewDecoder(strings.NewReader(text.Text))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&candidate); err == nil &&
					candidate.SchemaVersion == toolErrorSchemaV1 &&
					knownToolErrorCode(candidate.Code) && candidate.Message != "" {
					var extra any
					if err := decoder.Decode(&extra); err == io.EOF {
						failure = candidate
					}
				}
				break
			}
		}
		return model.NewError(failure.Code, "MCP tool "+name+": "+failure.Message)
	}
	if result.StructuredContent == nil {
		return fmt.Errorf("MCP tool %s omitted structured content", name)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return fmt.Errorf("encode MCP tool %s result: %w", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode MCP tool %s result: %w", name, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("decode MCP tool %s result: unexpected trailing JSON", name)
	}
	return nil
}

func (c *Client) Close() error {
	if c == nil || c.session == nil {
		return nil
	}
	return c.session.Close()
}
