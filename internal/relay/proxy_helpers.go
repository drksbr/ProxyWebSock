package relay

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

func compileACLs(patterns []string) ([]*regexp.Regexp, error) {
	acls := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile ACL %q: %w", pattern, err)
		}
		acls = append(acls, re)
	}
	return acls, nil
}

func parseProxyAuthorization(header string) (string, string, error) {
	if header == "" {
		return "", "", errors.New("missing proxy authorization")
	}
	const prefix = "Basic "
	if !strings.HasPrefix(strings.ToLower(header), strings.ToLower(prefix)) {
		return "", "", errors.New("unsupported proxy auth scheme")
	}
	encoded := strings.TrimSpace(header[len(prefix):])
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("decode proxy authorization: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid proxy authorization payload")
	}
	return parts[0], parts[1], nil
}

func splitHostPort(host string) (string, int, error) {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, port, nil
}

func writeProxyError(buf *bufio.ReadWriter, msg string) {
	_, _ = buf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n")
	_, _ = buf.WriteString(msg)
	_ = buf.Flush()
}
