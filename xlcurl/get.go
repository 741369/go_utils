package xlcurl

import (
	"context"
	"github.com/741369/go_utils/xlerror"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (c *Client) Get(ctx context.Context, uri string, timeout time.Duration, headers map[string]string,
	cookies ...[]*http.Cookie) (cancel context.CancelFunc, resp *http.Response, err error) {
	if c.client == nil {
		err = xlerror.New("httpClient not init")
		return
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		err = xlerror.Wrapf(err, "uri-%s, headers-%+v, cookies-%+v", uri, headers, cookies)
		return
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	if len(cookies) > 0 {
		for _, cookie := range cookies[0] {
			req.AddCookie(cookie)
		}
	}

	ctx, cancel = context.WithTimeout(ctx, timeout)
	req = req.WithContext(ctx)
	resp, err = c.client.Do(req)
	if err != nil {
		err = xlerror.Wrapf(err, "uri-%s, headers-%+v, cookies-%+v", uri, headers, cookies)
	}
	return
}

func (c *Client) SimpleGet(ctx context.Context, uri string, timeout time.Duration, headers map[string]string,
	cookies ...[]*http.Cookie) (statusCode int, body []byte, err error) {
	cancel, resp, err := c.Get(ctx, uri, timeout, headers, cookies...)
	if err != nil {
		return
	}
	defer cancel()
	defer resp.Body.Close()
	statusCode = resp.StatusCode
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		err = xlerror.Wrapf(err, "uri-%s, headers-%+v, cookies-%+v", uri, headers, cookies)
		return
	}
	return
}

func (c *Client) SimpleGetToMap(ctx context.Context, uri string, timeout time.Duration, headers map[string]string,
	cookies ...[]*http.Cookie) (m map[string]string, err error) {
	m = make(map[string]string)
	statusCode, body, err := c.SimpleGet(ctx, uri, timeout, headers, cookies...)
	if err != nil {
		return
	}
	if statusCode != 200 {
		err = xlerror.Errorf("status code is %d", statusCode)
		return
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		err = xlerror.Wrapf(err, "uri-%s, headers-%+v, cookies-%+v, body-%s", uri, headers, cookies, string(body))
		return
	}
	m = make(map[string]string)
	for key, item := range values {
		m[key] = strings.TrimSpace(item[0])
	}
	return
}
