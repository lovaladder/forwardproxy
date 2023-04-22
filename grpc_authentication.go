package forwardproxy

import (
	"context"
	"encoding/base64"
)

type GRPCAuthentication struct {
	Username string
	Password string
}

func NewGRPCAuthentication(username, password string) *GRPCAuthentication {
	return &GRPCAuthentication{
		Username: username,
		Password: password,
	}
}

func (g *GRPCAuthentication) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(g.Username+":"+g.Password)),
	}, nil
}

func (g *GRPCAuthentication) RequireTransportSecurity() bool {
	return true
}
