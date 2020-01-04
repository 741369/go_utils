package xlcurl

import (
	"net/http"
	"time"
)

type Client struct {
	client *http.Client
}

var DefaultTransport = &http.Transport{
	MaxIdleConns:          1200,
	MaxIdleConnsPerHost:   300,
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
	IdleConnTimeout:       90 * time.Second,
}

func DefaultClient() *Client {
	return NewClient(DefaultTransport)
}

func NewClient(transport *http.Transport) *Client {
	return &Client{
		client: &http.Client{
			Transport: transport,
		},
	}
}
