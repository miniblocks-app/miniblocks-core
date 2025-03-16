package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/miniblocks-app/miniblocks-core/errors"
	"go.uber.org/zap"
)

// Resp is a marker interface for possible response types.
type Resp interface{}

// Query is a generic structure to build requests with method, path, body, etc.
type Query[R Resp] struct {
	cli    Client
	Method string
	Path   string
	Body   []byte
	Form   url.Values
}

// NewQuery creates a new Query with default values.
func NewQuery[R Resp](c Client) Query[R] {
	return Query[R]{
		cli:    c,
		Method: http.MethodGet,
		Form:   url.Values{},
	}
}

func (p Query[R]) WithMethod(method string) Query[R] {
	p.Method = method
	return p
}

func (p Query[R]) WithPath(format string, v ...any) Query[R] {
	p.Path = fmt.Sprintf(format, v...)
	return p
}

func (p Query[R]) WithBody(body any) Query[R] {
	b, _ := json.Marshal(body)
	p.Body = b
	return p
}

func (p Query[R]) WithFormData(key, value string) Query[R] {
	p.Form.Set(key, value)
	return p
}

// Do executes the HTTP request and decodes the response into R.
func (p Query[R]) Do(ctx context.Context) (R, error) {
	var rsp R
	urlPath, err := url.JoinPath(p.cli.getBaseURL(), p.Path)
	if err != nil {
		return rsp, err
	}

	// We can optionally do some logging here if we have a *zap.Logger from the client
	restClient, ok := p.cli.(*RestClient)
	if ok && restClient.logger != nil {
		restClient.logger.Info("Sending request",
			zap.String("method", p.Method),
			zap.String("url", urlPath),
		)
	}

	var body io.Reader
	if len(p.Form) > 0 {
		body = bytes.NewBufferString(p.Form.Encode())
	} else if len(p.Body) > 0 {
		body = bytes.NewBuffer(p.Body)
	}
	httpRsp, err := p.cli.do(ctx, p.Method, urlPath, body)
	if err != nil {
		if ok && restClient.logger != nil {
			restClient.logger.Error("Error in HTTP request", zap.Error(err))
		}
		return rsp, err
	}
	defer httpRsp.Body.Close()

	// Check status code
	if httpRsp.StatusCode != http.StatusOK && httpRsp.StatusCode != http.StatusCreated {
		if ok && restClient.logger != nil {
			restClient.logger.Warn("Unexpected status code",
				zap.Int("statusCode", httpRsp.StatusCode),
				zap.String("method", p.Method),
				zap.String("url", urlPath),
			)
		}
	}

	switch httpRsp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		// proceed
	case http.StatusUnauthorized, http.StatusForbidden:
		return rsp, errors.ErrInvalidAuth
	case http.StatusNotFound:
		return rsp, errors.ErrNotFound
	case http.StatusTooManyRequests:
		return rsp, errors.ErrTooManyRequests
	default:
		return rsp, errors.ErrInternalAPICall
	}

	// Decode JSON response into rsp
	if err := json.NewDecoder(httpRsp.Body).Decode(&rsp); err != nil && err != io.EOF {
		if ok && restClient.logger != nil {
			restClient.logger.Error("Failed to decode JSON response", zap.Error(err))
		}
		return rsp, err
	}

	return rsp, nil
}
