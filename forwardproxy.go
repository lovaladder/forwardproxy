// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Caching is purposefully ignored.

package forwardproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/forwardproxy/httpclient"
	"github.com/caddyserver/forwardproxy/proto"
	"github.com/google/go-attestation/attest"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func init() {
	caddy.RegisterModule(Handler{})

	// Used for generating padding lengths. Not needed to be cryptographically secure.
	// Does not care about double seeding.
	rand.Seed(time.Now().UnixNano())

	// 为了修复打包错误
	// https://pkg.go.dev/github.com/google/go-attestation@v0.4.4-0.20230310182828-270ecbab1f21/x509
	_ = attest.OpenConfig{}
}

type ReaderWithReporter struct {
	h      *Handler
	userId string
	inner  io.ReadCloser
}

func (r *ReaderWithReporter) Read(p []byte) (n int, err error) {
	n, err = r.inner.Read(p)
	if n > 0 {
		err = r.h.logDataUsage(r.userId, int64(n))
	}
	return
}

func (r *ReaderWithReporter) Close() error {
	return r.inner.Close()
}

type DataUsage struct {
	UserId string
	Usage  int64
}

type UserData struct {
	dataRemainingLock sync.Mutex
	dataRemaining     int64
	authKey           string
	connsLock         sync.Mutex
	conns             map[string]map[string]io.ReadCloser
}

// Handler implements a forward proxy.
//
// EXPERIMENTAL: This handler is still experimental and subject to breaking changes.
type Handler struct {
	logger *zap.Logger

	// Filename of the PAC file to serve.
	PACPath string `json:"pac_path,omitempty"`

	// If true, the Forwarded header will not be augmented with your IP address.
	HideIP bool `json:"hide_ip,omitempty"`

	// If true, the Via heaeder will not be added.
	HideVia bool `json:"hide_via,omitempty"`

	// Host(s) (and ports) of the proxy. When you configure a client,
	// you will give it the host (and port) of the proxy to use.
	Hosts caddyhttp.MatchHost `json:"hosts,omitempty"`

	// Optional probe resistance. (See documentation.)
	ProbeResistance *ProbeResistance `json:"probe_resistance,omitempty"`

	// How long to wait before timing out initial TCP connections.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// Optionally configure an upstream proxy to use.
	Upstream string `json:"upstream,omitempty"`

	// Access control list.
	ACL []ACLRule `json:"acl,omitempty"`

	// Ports to be allowed to connect to (if non-empty).
	AllowedPorts []int `json:"allowed_ports,omitempty"`

	httpTransport *http.Transport

	// overridden dialContext allows us to redirect requests to upstream proxy
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
	upstream    *url.URL // address of upstream proxy

	aclRules []aclRule

	GrpcServer string `json:"grpc_server,omitempty"`
	ServerId   string `json:"server_id,omitempty"`
	SecretKey  string `json:"secret_key,omitempty"`
	UseTLS     bool   `json:"use_tls,omitempty"`

	reconnectCh         chan struct{}
	reconnecting        bool
	grpcContextCancelFn func()
	dashboardClient     proto.DashboardClient
	usersLock           *sync.RWMutex
	users               map[string]*UserData
	dataUsageCh         chan DataUsage
	dataUsageStatLock   *sync.Mutex
	dataUsageStat       map[string]int64
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision ensures that h is set up properly before use.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	h.usersLock = new(sync.RWMutex)
	h.users = make(map[string]*UserData)
	h.dataUsageCh = make(chan DataUsage, 2000)
	h.dataUsageStatLock = new(sync.Mutex)
	h.dataUsageStat = make(map[string]int64)
	h.reconnectCh = make(chan struct{})

	if h.DialTimeout <= 0 {
		h.DialTimeout = caddy.Duration(30 * time.Second)
	}

	h.httpTransport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        50,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// access control lists
	for _, rule := range h.ACL {
		for _, subj := range rule.Subjects {
			ar, err := newACLRule(subj, rule.Allow)
			if err != nil {
				return err
			}
			h.aclRules = append(h.aclRules, ar)
		}
	}
	for _, ipDeny := range []string{
		"10.0.0.0/8",
		"127.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fe80::/10",
	} {
		ar, err := newACLRule(ipDeny, false)
		if err != nil {
			return err
		}
		h.aclRules = append(h.aclRules, ar)
	}
	h.aclRules = append(h.aclRules, &aclAllRule{allow: true})

	if h.ProbeResistance != nil && len(h.ProbeResistance.Domain) > 0 {
		h.logger.Debug("Secret domain used to connect to proxy: " + h.ProbeResistance.Domain)
	}

	dialer := &net.Dialer{
		Timeout:   time.Duration(h.DialTimeout),
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	h.dialContext = dialer.DialContext
	h.httpTransport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return h.dialContextCheckACL(ctx, network, address)
	}

	if h.Upstream != "" {
		upstreamURL, err := url.Parse(h.Upstream)
		if err != nil {
			return fmt.Errorf("bad upstream URL: %v", err)
		}
		h.upstream = upstreamURL

		if !isLocalhost(h.upstream.Hostname()) && h.upstream.Scheme != "https" {
			return errors.New("insecure schemes are only allowed to localhost upstreams")
		}

		registerHTTPDialer := func(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
			// CONNECT request is proxied as-is, so we don't care about target url, but it could be
			// useful in future to implement policies of choosing between multiple upstream servers.
			// Given dialer is not used, since it's the same dialer provided by us.
			d, err := httpclient.NewHTTPConnectDialer(h.upstream.String())
			if err != nil {
				return nil, err
			}
			d.Dialer = *dialer
			if isLocalhost(h.upstream.Hostname()) && h.upstream.Scheme == "https" {
				// disabling verification helps with testing the package and setups
				// either way, it's impossible to have a legit TLS certificate for "127.0.0.1" - TODO: not true anymore
				h.logger.Debug("Localhost upstream detected, disabling verification of TLS certificate")
				d.DialTLS = func(network string, address string) (net.Conn, string, error) {
					conn, err := tls.Dial(network, address, &tls.Config{InsecureSkipVerify: true})
					if err != nil {
						return nil, "", err
					}
					return conn, conn.ConnectionState().NegotiatedProtocol, nil
				}
			}
			return d, nil
		}
		proxy.RegisterDialerType("https", registerHTTPDialer)
		proxy.RegisterDialerType("http", registerHTTPDialer)

		upstreamDialer, err := proxy.FromURL(h.upstream, dialer)
		if err != nil {
			return errors.New("failed to create proxy to upstream: " + err.Error())
		}

		if ctxDialer, ok := upstreamDialer.(dialContexter); ok {
			// upstreamDialer has DialContext - use it
			h.dialContext = ctxDialer.DialContext
		} else {
			// upstreamDialer does not have DialContext - ignore the context :(
			h.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
				return upstreamDialer.Dial(network, address)
			}
		}
	}

	go h.reconnectDashboard()
	h.reconnectCh <- struct{}{}

	return nil
}

func (h *Handler) innerReconnectDashboard() {
	defer func() {
		h.reconnecting = false
	}()
	time.Sleep(time.Second * 3) // wait a bit before reconnecting
	h.logger.Info("Reconnecting to dashboard")

	var securityOption grpc.DialOption
	if h.UseTLS {
		securityOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
	} else {
		securityOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	var grpcConn *grpc.ClientConn
	var err error
OUTER:
	for {
		grpcConn, err = grpc.Dial(h.GrpcServer, securityOption, grpc.WithPerRPCCredentials(NewGRPCAuthentication(h.ServerId, h.SecretKey, h.UseTLS)))
		if err == nil {
			for i := 0; i < 3; i++ {
				if grpcConn.GetState() == connectivity.Ready {
					break OUTER
				}
				time.Sleep(time.Second)
			}
			err = errors.New("grpc connection is not ready")
			grpcConn.Close()
		}
		h.logger.Error("Error connecting to dashboard", zap.Error(err))
	}

	h.dashboardClient = proto.NewDashboardClient(grpcConn)

	ctx, cancel := context.WithCancel(context.Background())
	h.grpcContextCancelFn = cancel

	go h.handleUsersUpdate(ctx)
	go h.reportDataUsage(ctx)
}

func (h *Handler) reconnectDashboard() {
	for range h.reconnectCh {
		if h.reconnecting {
			continue
		}
		h.reconnecting = true
		if h.grpcContextCancelFn != nil {
			h.grpcContextCancelFn()
			h.grpcContextCancelFn = nil
		}
		go h.innerReconnectDashboard()
	}
}

func (h *Handler) reportDataUsage(ctx context.Context) {
	h.logger.Info("Start reporting data usage")
	defer func() {
		h.reconnectCh <- struct{}{}
	}()
	defer h.logger.Info("Stop reporting data usage")

	stream, err := h.dashboardClient.UsageStramingUpdate(ctx)
	if err != nil {
		h.logger.Error("Error connecting to dashboard", zap.Error(err))
		return
	}

	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var list []*proto.Usage
			h.dataUsageStatLock.Lock()
			for userId, used := range h.dataUsageStat {
				if used <= 0 {
					continue
				}
				var usage proto.Usage
				usage.UserId = userId
				usage.DataUsed = used
				list = append(list, &usage)
				h.dataUsageStat[userId] = 0
			}
			h.dataUsageStatLock.Unlock()
			h.logger.Debug("Report data usage", zap.Int("count", len(list)))
			if len(list) > 0 {
				if err := stream.Send(&proto.RepeatedUsage{Usages: list}); err != nil {
					h.logger.Error("Error report data usage send", zap.Error(err))
					return
				}
			}
		case data := <-h.dataUsageCh:
			h.dataUsageStatLock.Lock()
			if _, has := h.dataUsageStat[data.UserId]; has {
				h.dataUsageStat[data.UserId], _ = SafeMath.Add(h.dataUsageStat[data.UserId], data.Usage)
			}
			h.dataUsageStatLock.Unlock()
		}
	}
}

func (h *Handler) handleUsersUpdate(ctx context.Context) {
	h.logger.Info("Start getting users update")
	defer func() {
		h.reconnectCh <- struct{}{}
	}()
	defer h.logger.Info("Stop getting users update")
	usersUpdate, err := h.dashboardClient.UserStramingUpdate(ctx, &proto.Empty{})
	if err != nil {
		h.logger.Error("Error getting users update init", zap.Error(err))
		return
	}
	for {
		msg, err := usersUpdate.Recv()
		if err != nil {
			h.logger.Error("Error getting users update recv: ", zap.Error(err))
			return
		}
		users := msg.GetUsers()
		h.logger.Debug("Users update", zap.Any("users", users))

		var wg sync.WaitGroup
		wg.Add(len(users))

		for _, user := range users {
			userId := user.GetUserId()
			userAuthKey := user.GetAuthKey()
			dataRemaining := user.GetDataRemaining()
			go lo.Try(func() error {
				defer wg.Done()
				// 如果没有用户，添加用户
				h.usersLock.RLock()
				data, has := h.users[userId]
				h.usersLock.RUnlock()

				if !has {
					// 新增用户
					h.usersLock.Lock()
					h.dataUsageStatLock.Lock()
					h.users[userId] = &UserData{
						dataRemaining: dataRemaining,
						authKey:       userAuthKey,
						conns:         make(map[string]map[string]io.ReadCloser),
					}
					h.dataUsageStat[userId] = 0
					h.dataUsageStatLock.Unlock()
					h.usersLock.Unlock()
					return nil
				}
				data.dataRemaining = dataRemaining
				// 如果用户流量用完或密码发生了改变，踢出所有连接
				if dataRemaining <= 0 || data.authKey != userAuthKey {
					data.connsLock.Lock()
					for _, conns := range data.conns {
						for _, conn := range conns {
							conn.Close()
						}
					}
					data.conns = make(map[string]map[string]io.ReadCloser)
					data.connsLock.Unlock()
				}
				// 如果用户流量用完，删除用户
				if dataRemaining <= 0 {
					// 删除用户
					h.usersLock.Lock()
					h.dataUsageStatLock.Lock()
					delete(h.users, userId)
					delete(h.dataUsageStat, userId)
					h.dataUsageStatLock.Unlock()
					h.usersLock.Unlock()
				}
				return nil
			})
		}

		wg.Wait()
	}
}

func (h *Handler) logDataUsage(userId string, dataUsed int64) error {
	h.usersLock.RLock()
	defer h.usersLock.RUnlock()
	user, ok := h.users[userId]
	if !ok {
		return errors.New("user not found")
	}
	user.dataRemainingLock.Lock()
	defer user.dataRemainingLock.Unlock()
	var err error
	user.dataRemaining, err = SafeMath.Sub(user.dataRemaining, dataUsed)
	h.dataUsageCh <- DataUsage{
		UserId: userId,
		Usage:  dataUsed,
	}
	return err
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	h.logger.Debug("ServeHTTP", zap.Any("header", r.Header))
	// start by splitting the request host and port
	reqHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		reqHost = r.Host // OK; probably just didn't have a port
	}

	userAuthRet := h.checkCredentials(r)
	if h.ProbeResistance != nil && len(h.ProbeResistance.Domain) > 0 && reqHost == h.ProbeResistance.Domain {
		return serveHiddenPage(w, userAuthRet.Error())
	}
	h.logger.Debug("checkCredentials", zap.Any("userAuthError", userAuthRet.Error()), zap.Any("check", h.Hosts.Match(r) && r.Method != http.MethodConnect))
	if h.Hosts.Match(r) && r.Method != http.MethodConnect {
		// Always pass non-CONNECT requests to hostname
		// Pass CONNECT requests only if probe resistance is enabled and not authenticated
		if h.shouldServePACFile(r) {
			return h.servePacFile(w, r)
		}
		return next.ServeHTTP(w, r)
	}
	if userAuthRet.IsError() {
		if h.ProbeResistance != nil {
			// probe resistance is requested and requested URI does not match secret domain;
			// act like this proxy handler doesn't even exist (pass thru to next handler)
			return next.ServeHTTP(w, r)
		}
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"")
		return caddyhttp.Error(http.StatusProxyAuthRequired, userAuthRet.Error())
	}

	if r.ProtoMajor != 1 && r.ProtoMajor != 2 && r.ProtoMajor != 3 {
		return caddyhttp.Error(http.StatusHTTPVersionNotSupported,
			fmt.Errorf("unsupported HTTP major version: %d", r.ProtoMajor))
	}

	ctx := context.Background()
	if !h.HideIP {
		ctxHeader := make(http.Header)
		for k, v := range r.Header {
			if kL := strings.ToLower(k); kL == "forwarded" || kL == "x-forwarded-for" {
				ctxHeader[k] = v
			}
		}
		ctxHeader.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
		ctx = context.WithValue(ctx, httpclient.ContextKeyHeader{}, ctxHeader)
	}

	if err = h.logDataUsage(userAuthRet.MustGet(), countHttpRequestHeadLength(r)); err != nil {
		return caddyhttp.Error(http.StatusForbidden, err)
	}

	if r.Method == http.MethodConnect {
		if r.ProtoMajor == 2 || r.ProtoMajor == 3 {
			if len(r.URL.Scheme) > 0 || len(r.URL.Path) > 0 {
				return caddyhttp.Error(http.StatusBadRequest,
					fmt.Errorf("CONNECT request has :scheme and/or :path pseudo-header fields"))
			}
		}

		// HTTP CONNECT Fast Open. We merely close the connection if Open fails.
		wFlusher, ok := w.(http.Flusher)
		if !ok {
			return caddyhttp.Error(http.StatusInternalServerError,
				fmt.Errorf("ResponseWriter doesn't implement http.Flusher"))
		}
		// Creates a padding of [30, 30+32)
		paddingLen := rand.Intn(32) + 30
		padding := make([]byte, paddingLen)
		bits := rand.Uint64()
		for i := 0; i < 16; i++ {
			// Codes that won't be Huffman coded.
			padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
			bits >>= 4
		}
		for i := 16; i < paddingLen; i++ {
			padding[i] = '~'
		}
		w.Header().Set("Padding", string(padding))
		w.WriteHeader(http.StatusOK)
		wFlusher.Flush()

		hostPort := r.URL.Host
		if hostPort == "" {
			hostPort = r.Host
		}
		targetConn, err := h.dialContextCheckACL(ctx, "tcp", hostPort)
		if err != nil {
			return err
		}
		if targetConn == nil {
			// safest to check both error and targetConn afterwards, in case fp.dial (potentially unstable
			// from x/net/proxy) misbehaves and returns both nil or both non-nil
			return caddyhttp.Error(http.StatusForbidden,
				fmt.Errorf("hostname %s is not allowed", r.URL.Hostname()))
		}
		defer targetConn.Close()

		switch r.ProtoMajor {
		case 1: // http1: hijack the whole flow
			return h.serveHijack(userAuthRet.MustGet(), w, targetConn)
		case 2: // http2: keep reading from "request" and writing into same response
			fallthrough
		case 3:
			defer r.Body.Close()
			return h.dualStream(userAuthRet.MustGet(), r.RemoteAddr, targetConn, r.Body, w, r.Header.Get("Padding") != "")
		}

		panic("There was a check for http version, yet it's incorrect")
	}

	// Scheme has to be appended to avoid `unsupported protocol scheme ""` error.
	// `http://` is used, since this initial request itself is always HTTP, regardless of what client and server
	// may speak afterwards.
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.Proto = "HTTP/1.1"
	r.ProtoMajor = 1
	r.ProtoMinor = 1
	r.RequestURI = ""

	removeHopByHop(r.Header)

	if !h.HideIP {
		r.Header.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
	}

	// https://tools.ietf.org/html/rfc7230#section-5.7.1
	if !h.HideVia {
		r.Header.Add("Via", strconv.Itoa(r.ProtoMajor)+"."+strconv.Itoa(r.ProtoMinor)+" caddy")
	}

	var response *http.Response
	if h.upstream == nil {
		// non-upstream request uses httpTransport to reuse connections
		if r.Body != nil &&
			(r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || r.Method == "TRACE") {
			// make sure request is idempotent and could be retried by saving the Body
			// None of those methods are supposed to have body,
			// but we still need to copy the r.Body, even if it's empty
			rBodyBuf, err := io.ReadAll(r.Body)
			if err != nil {
				return caddyhttp.Error(http.StatusBadRequest,
					fmt.Errorf("failed to read request body: %v", err))
			}
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(rBodyBuf)), nil
			}
			r.Body, _ = r.GetBody()
		}
		r.Body = &ReaderWithReporter{h: h, inner: r.Body, userId: userAuthRet.MustGet()}
		response, err = h.httpTransport.RoundTrip(r)
	} else {
		// Upstream requests don't interact well with Transport: connections could always be
		// reused, but Transport thinks they go to different Hosts, so it spawns tons of
		// useless connections.
		// Just use dialContext, which will multiplex via single connection, if http/2
		if creds := h.upstream.User.String(); creds != "" {
			// set upstream credentials for the request, if needed
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		}
		if r.URL.Port() == "" {
			r.URL.Host = net.JoinHostPort(r.URL.Host, "80")
		}
		upsConn, err := h.dialContext(ctx, "tcp", r.URL.Host)
		if err != nil {
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to dial upstream: %v", err))
		}
		err = r.Write(upsConn)
		if err != nil {
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to write upstream request: %v", err))
		}
		r.Body = &ReaderWithReporter{h: h, inner: r.Body, userId: userAuthRet.MustGet()}
		response, err = http.ReadResponse(bufio.NewReader(upsConn), r)
		if err != nil {
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to read upstream response: %v", err))
		}
	}
	r.Body.Close()

	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if _, ok := err.(caddyhttp.HandlerError); ok {
			return err
		}
		return caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to read response: %v", err))
	}

	return h.forwardResponse(userAuthRet.MustGet(), r.RemoteAddr, w, response)
}

func (h *Handler) checkCredentials(r *http.Request) mo.Result[string] {
	pa := strings.Split(r.Header.Get("Proxy-Authorization"), " ")
	if len(pa) != 2 {
		return mo.Err[string](errors.New("Proxy-Authorization is required! Expected format: <type> <credentials>"))
	}
	if strings.ToLower(pa[0]) != "basic" {
		return mo.Err[string](errors.New("auth type is not supported"))
	}

	credentials, err := base64.RawStdEncoding.DecodeString(pa[1])
	if err == nil {
		userId, userAuthKey, ok := strings.Cut(string(credentials), ":")
		if ok {
			h.usersLock.RLock()
			defer h.usersLock.RUnlock()
			data, has := h.users[userId]
			if has && data.authKey == userAuthKey {
				if data.dataRemaining <= 0 {
					return mo.Err[string](errors.New("user has no data remaining"))
				}
				return mo.Ok(userId)
			}
		}
	}

	return mo.Err[string](errors.New("invalid credentials"))
}

func (h Handler) shouldServePACFile(r *http.Request) bool {
	return len(h.PACPath) > 0 && r.URL.Path == h.PACPath
}

func (h Handler) servePacFile(w http.ResponseWriter, r *http.Request) error {
	fmt.Fprintf(w, pacFile, r.Host)
	// fmt.Fprintf(w, pacFile, h.hostname, h.port)
	return nil
}

// dialContextCheckACL enforces Access Control List and calls fp.DialContext
func (h Handler) dialContextCheckACL(ctx context.Context, network, hostPort string) (net.Conn, error) {
	var conn net.Conn

	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		// return nil, &proxyError{S: "Network " + network + " is not supported", Code: http.StatusBadRequest}
		return nil, caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("network %s is not supported", network))
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		// return nil, &proxyError{S: err.Error(), Code: http.StatusBadRequest}
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.upstream != nil {
		// if upstreaming -- do not resolve locally nor check acl
		conn, err = h.dialContext(ctx, network, hostPort)
		if err != nil {
			// return conn, &proxyError{S: err.Error(), Code: http.StatusBadGateway}
			return conn, caddyhttp.Error(http.StatusBadGateway, err)
		}
		return conn, nil
	}

	if !h.portIsAllowed(port) {
		// return nil, &proxyError{S: "port " + port + " is not allowed", Code: http.StatusForbidden}
		return nil, caddyhttp.Error(http.StatusForbidden,
			fmt.Errorf("port %s is not allowed", port))
	}

	// in case IP was provided, net.LookupIP will simply return it
	IPs, err := net.LookupIP(host)
	if err != nil {
		// return nil, &proxyError{S: fmt.Sprintf("Lookup of %s failed: %v", host, err),
		// Code: http.StatusBadGateway}
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("lookup of %s failed: %v", host, err))
	}

	// This is net.Dial's default behavior: if the host resolves to multiple IP addresses,
	// Dial will try each IP address in order until one succeeds
	for _, ip := range IPs {
		if !h.hostIsAllowed(host, ip) {
			continue
		}

		conn, err = h.dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}

	return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
}

func (h Handler) hostIsAllowed(hostname string, ip net.IP) bool {
	for _, rule := range h.aclRules {
		switch rule.tryMatch(ip, hostname) {
		case aclDecisionDeny:
			return false
		case aclDecisionAllow:
			return true
		}
	}
	// TODO: convert this to log entry
	// fmt.Println("ERROR: no acl match for ", hostname, ip) // shouldn't happen
	return false
}

func (h Handler) portIsAllowed(port string) bool {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if portInt <= 0 || portInt > 65535 {
		return false
	}
	if len(h.AllowedPorts) == 0 {
		return true
	}
	isAllowed := false
	for _, p := range h.AllowedPorts {
		if p == portInt {
			isAllowed = true
			break
		}
	}
	return isAllowed
}

func serveHiddenPage(w http.ResponseWriter, authErr error) error {
	const hiddenPage = `<html>
<head>
  <title>Hidden Proxy Page</title>
</head>
<body>
<h1>Hidden Proxy Page!</h1>
%s<br/>
</body>
</html>`
	const AuthFail = "Please authenticate yourself to the proxy."
	const AuthOk = "Congratulations, you are successfully authenticated to the proxy! Go browse all the things!"

	w.Header().Set("Content-Type", "text/html")
	if authErr != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		w.Write([]byte(fmt.Sprintf(hiddenPage, AuthFail)))
		return authErr
	}
	w.Write([]byte(fmt.Sprintf(hiddenPage, AuthOk)))
	return nil
}

// Hijacks the connection from ResponseWriter, writes the response and proxies data between targetConn
// and hijacked connection.
func (h *Handler) serveHijack(userId string, w http.ResponseWriter, targetConn net.Conn) error {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("ResponseWriter does not implement http.Hijacker"))
	}
	clientConn, bufReader, err := hijacker.Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("hijack failed: %v", err))
	}
	defer clientConn.Close()
	// bufReader may contain unprocessed buffered data from the client.
	if bufReader != nil {
		// snippet borrowed from `proxy` plugin
		if n := bufReader.Reader.Buffered(); n > 0 {
			rbuf, err := bufReader.Reader.Peek(n)
			if err != nil {
				return caddyhttp.Error(http.StatusBadGateway, err)
			}
			targetConn.Write(rbuf)
		}
	}
	// Since we hijacked the connection, we lost the ability to write and flush headers via w.
	// Let's handcraft the response and send it manually.
	res := &http.Response{StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	res.Header.Set("Server", "Caddy")

	err = res.Write(clientConn)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to send response to client: %v", err))
	}

	return h.dualStream(userId, clientConn.RemoteAddr().String(), targetConn, clientConn, clientConn, false)
}

const (
	NoPadding        = 0
	AddPadding       = 1
	RemovePadding    = 2
	NumFirstPaddings = 8
)

// onConnetionOpen 新链接
func (h *Handler) onConnetionOpen(userId, remoteAddr string, target io.ReadCloser) error {
	h.usersLock.RLock()
	defer h.usersLock.RUnlock()
	user, ok := h.users[userId]
	if !ok {
		target.Close()
		return fmt.Errorf("user %s not found", userId)
	}
	user.connsLock.Lock()
	defer user.connsLock.Unlock()
	if _, has := user.conns[userId]; !has {
		user.conns[userId] = make(map[string]io.ReadCloser)
	}
	user.conns[userId][remoteAddr] = target
	return nil
}

// onConnetionClose 链接关闭
func (h *Handler) onConnetionClose(userId, remoteAddr string) {
	h.usersLock.RLock()
	defer h.usersLock.RUnlock()
	if user := h.users[userId]; user != nil {
		user.connsLock.Lock()
		defer user.connsLock.Unlock()
		delete(user.conns[userId], remoteAddr)
	}
}

// Copies data target->clientReader and clientWriter->target, and flushes as needed
// Returns when clientWriter-> target stream is done.
// Caddy should finish writing target -> clientReader.
func (h *Handler) dualStream(userId, remoteAddr string, target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer, padding bool) error {
	h.onConnetionOpen(userId, remoteAddr, target)
	defer h.onConnetionClose(userId, remoteAddr)

	stream := func(w io.Writer, r io.Reader, paddingType int) error {
		// copy bytes from r to w
		buf := *bufferPool.Get().(*[]byte)
		buf = buf[0:cap(buf)]
		_, _err := h.flushingIoCopy(userId, w, r, buf, paddingType)
		bufferPool.Put(&buf)
		if cw, ok := w.(closeWriter); ok {
			cw.CloseWrite()
		}
		return _err
	}
	if padding {
		go stream(target, clientReader, RemovePadding)
		return stream(clientWriter, target, AddPadding)
	} else {
		go stream(target, clientReader, NoPadding)
		return stream(clientWriter, target, NoPadding)
	}
}

type closeWriter interface {
	CloseWrite() error
}

// flushingIoCopy is analogous to buffering io.Copy(), but also attempts to flush on each iteration.
// If dst does not implement http.Flusher(e.g. net.TCPConn), it will do a simple io.CopyBuffer().
// Reasoning: http2ResponseWriter will not flush on its own, so we have to do it manually.
func (h *Handler) flushingIoCopy(userId string, dst io.Writer, src io.Reader, buf []byte, paddingType int) (written int64, err error) {
	flusher, hasFlusher := dst.(http.Flusher)
	var numPadding int
	for {
		var nr int
		var er error
		if paddingType == AddPadding && numPadding < NumFirstPaddings {
			numPadding++
			paddingSize := rand.Intn(256)
			maxRead := 65536 - 3 - paddingSize
			nr, er = src.Read(buf[3:maxRead])
			if nr > 0 {
				buf[0] = byte(nr / 256)
				buf[1] = byte(nr % 256)
				buf[2] = byte(paddingSize)
				for i := 0; i < paddingSize; i++ {
					buf[3+nr+i] = 0
				}
				nr += 3 + paddingSize
			}
		} else if paddingType == RemovePadding && numPadding < NumFirstPaddings {
			numPadding++
			nr, er = io.ReadFull(src, buf[0:3])
			if nr > 0 {
				nr = int(buf[0])*256 + int(buf[1])
				paddingSize := int(buf[2])
				nr, er = io.ReadFull(src, buf[0:nr])
				if nr > 0 {
					var junk [256]byte
					_, er = io.ReadFull(src, junk[0:paddingSize])
				}
			}
		} else {
			nr, er = src.Read(buf)
		}
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if hasFlusher {
				flusher.Flush()
			}
			if nw > 0 {
				written += int64(nw)
				if err = h.logDataUsage(userId, int64(nw)); err != nil {
					break
				}
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

// Removes hop-by-hop headers, and writes response into ResponseWriter.
func (h *Handler) forwardResponse(userId, remoteAddr string, w http.ResponseWriter, response *http.Response) error {
	h.onConnetionOpen(userId, remoteAddr, response.Body)
	defer h.onConnetionClose(userId, remoteAddr)

	w.Header().Del("Server") // remove Server: Caddy, append via instead
	w.Header().Add("Via", strconv.Itoa(response.ProtoMajor)+"."+strconv.Itoa(response.ProtoMinor)+" caddy")

	for header, values := range response.Header {
		for _, val := range values {
			w.Header().Add(header, val)
		}
	}
	removeHopByHop(w.Header())
	w.WriteHeader(response.StatusCode)
	buf := *bufferPool.Get().(*[]byte)
	buf = buf[0:cap(buf)]
	_, err := h.CopyBufferObserve(userId, w, response.Body, buf)
	bufferPool.Put(&buf)
	return err
}

func removeHopByHop(header http.Header) {
	connectionHeaders := header.Get("Connection")
	for _, h := range strings.Split(connectionHeaders, ",") {
		header.Del(strings.TrimSpace(h))
	}
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

var hopByHopHeaders = []string{
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Upgrade",
	"Connection",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
}

const pacFile = `
function FindProxyForURL(url, host) {
	if (host === "127.0.0.1" || host === "::1" || host === "localhost")
		return "DIRECT";
	return "HTTPS %s";
}
`

var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 64*1024)
		return &buf
	},
}

////// used during provision only

func isLocalhost(hostname string) bool {
	return hostname == "localhost" ||
		hostname == "127.0.0.1" ||
		hostname == "::1"
}

type dialContexter interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ProbeResistance configures probe resistance.
type ProbeResistance struct {
	Domain string `json:"domain,omitempty"`
}

func readLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hostnames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hostnames = append(hostnames, scanner.Text())
	}

	return hostnames, scanner.Err()
}

func countHttpRequestHeadLength(r *http.Request) int64 {
	var length int64
	length += int64(len(r.Method))
	length += int64(len(r.URL.String()))
	length += int64(len(r.Proto))
	length += 2 // CRLF
	for k, v := range r.Header {
		length += int64(len(k))
		length += int64(len(v))
		length += 4 // ": " + CRLF
	}
	length += 2 // CRLF
	return length
}

func (h *Handler) CopyBufferObserve(userId string, dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	if buf != nil && len(buf) == 0 {
		panic("empty buffer in CopyBuffer")
	}
	return h.copyBuffer(userId, dst, src, buf)
}

func (h *Handler) copyBuffer(userId string, dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("net: invalid Write result")
				}
			}
			written += int64(nw)
			// 扣减用户流量
			if err = h.logDataUsage(userId, int64(nw)); err != nil {
				break
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
