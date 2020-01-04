package xlcurl

import (
	"bytes"
	"context"
	"github.com/741369/go_utils/xlerror"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

func (c *Client) Post(ctx context.Context, url string, body io.Reader, timeout time.Duration,
	headers map[string]string, cookies ...[]*http.Cookie) (cancel context.CancelFunc, resp *http.Response, err error) {
	if c.client == nil {
		err = xlerror.Errorf("%s", "httpClient not init")
		return
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		err = xlerror.Wrapf(err, "uri-%s, headers-%+v, cookies-%+v", url, headers, cookies)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if len(cookies) > 0 {
		for _, cookie := range cookies[0] {
			req.AddCookie(cookie)
		}
	}

	ctx, cancel = context.WithTimeout(ctx, timeout)
	resp, err = c.client.Do(req.WithContext(ctx))
	if err != nil {
		err = xlerror.Wrapf(err, "uri-%s, headers-%+v, cookies-%+v", url, headers, cookies)
	}
	return
}

func (c *Client) SimplePost(ctx context.Context, url string, params []byte, timeout time.Duration,
	headers map[string]string, cookies ...[]*http.Cookie) (statusCode int, body []byte, err error) {
	cancel, resp, err := c.Post(ctx, url, bytes.NewBuffer(params), timeout, headers, cookies...)
	if err != nil {
		return
	}

	defer cancel()
	defer resp.Body.Close()

	statusCode = resp.StatusCode
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	return
}
