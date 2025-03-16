package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httputil"

	"go.uber.org/zap"
)

// Client is an interface for making HTTP calls.
type Client interface {
	getBaseURL() string
	do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error)
}

// RestClientConfig holds configuration for the RestClient.
type RestClientConfig struct {
	Token   string
	BaseUrl string
	Dump    bool
}

// RestClient is an HTTP client wrapper that uses zap for logging.
type RestClient struct {
	RestClientConfig
	logger *zap.Logger
	httpC  http.Client
}

// NewRestClient initializes a RestClient with a zap logger.
func NewRestClient(logger *zap.Logger, config RestClientConfig) *RestClient {
	return &RestClient{
		RestClientConfig: config,
		logger:           logger,
		httpC: http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// do performs an HTTP request using the method, url, and body, and optionally dumps request/response.
func (c *RestClient) do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		c.logger.Error("Failed to create new request", zap.Error(err))
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if c.Dump {
		bbReqDump, _ := httputil.DumpRequestOut(req, true)
		c.logger.Debug("Request ready to be sent",
			zap.String("method", req.Method),
			zap.String("url", req.URL.String()),
			zap.String("requestDump", string(bbReqDump)),
		)
	}

	rsp, err := c.httpC.Do(req)
	if err != nil {
		c.logger.Error("Failed to do HTTP request", zap.Error(err))
		return nil, err
	}

	if c.Dump {
		bbRspDump, _ := httputil.DumpResponse(rsp, true)
		c.logger.Debug("Response received",
			zap.String("method", req.Method),
			zap.String("url", req.URL.String()),
			zap.Int("status", rsp.StatusCode),
			zap.String("responseDump", string(bbRspDump)),
		)
	}

	return rsp, nil
}

func (c *RestClient) getBaseURL() string {
	return c.RestClientConfig.BaseUrl
}
