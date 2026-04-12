package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

const (
	diagnosticStepResolve = "resolve"
	diagnosticStepDial    = "dial"
	diagnosticStepTLS     = "tls"
)

func (a *agent) runDiagnostic(req protocol.DiagnosticRequest) protocol.DiagnosticResponse {
	startedAt := time.Now().UTC()
	resp := protocol.DiagnosticResponse{
		RequestID: req.RequestID,
		StartedAt: startedAt.UnixNano(),
	}
	defer func() {
		resp.FinishedAt = time.Now().UTC().UnixNano()
	}()

	if strings.TrimSpace(req.Host) == "" {
		resp.Error = "diagnostic host is required"
		return resp
	}
	if req.Port == 0 {
		resp.Error = "diagnostic port is required"
		return resp
	}
	if a.resolver == nil {
		a.resolver = newDialResolver(a.opts.resolverConfig())
	}

	timeout := time.Duration(req.TimeoutMillis) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(a.opts.dialTimeoutMs) * time.Millisecond
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	planStepStarted := time.Now()
	plan, err := a.resolver.resolvePlan(ctx, req.Host, req.OverrideAddress)
	resolveStep := protocol.DiagnosticStepResult{
		Step:           diagnosticStepResolve,
		DurationMillis: durationMillis(time.Since(planStepStarted)),
	}
	if err != nil {
		resolveStep.Message = err.Error()
		resp.Error = err.Error()
		resp.Steps = append(resp.Steps, resolveStep)
		return resp
	}
	resolveStep.Success = true
	resolveStep.ResolutionSource = plan.source
	resolveStep.Addresses = append([]string(nil), plan.addresses...)
	resolveStep.Message = fmt.Sprintf("%d enderecos resolvidos", len(plan.addresses))
	resp.Steps = append(resp.Steps, resolveStep)

	dialStepStarted := time.Now()
	conn, selectedAddress, dialMessage, dialErr := a.resolver.dialDiagnostic(ctx, plan, req.Port)
	dialStep := protocol.DiagnosticStepResult{
		Step:            diagnosticStepDial,
		DurationMillis:  durationMillis(time.Since(dialStepStarted)),
		SelectedAddress: selectedAddress,
		Message:         dialMessage,
	}
	if dialErr != nil {
		dialStep.Message = dialErr.Error()
		resp.Error = dialErr.Error()
		resp.Steps = append(resp.Steps, dialStep)
		return resp
	}
	dialStep.Success = true
	resp.Steps = append(resp.Steps, dialStep)
	defer conn.Close()

	if !req.TLSEnabled {
		return resp
	}

	tlsStepStarted := time.Now()
	tlsStep, tlsErr := runTLSDiagnostic(ctx, conn, req)
	tlsStep.DurationMillis = durationMillis(time.Since(tlsStepStarted))
	tlsStep.Step = diagnosticStepTLS
	tlsStep.SelectedAddress = selectedAddress
	if tlsErr != nil {
		tlsStep.Message = tlsErr.Error()
		resp.Error = tlsErr.Error()
		resp.Steps = append(resp.Steps, tlsStep)
		return resp
	}
	tlsStep.Success = true
	resp.Steps = append(resp.Steps, tlsStep)
	return resp
}

func (r *dialResolver) dialDiagnostic(ctx context.Context, plan dialPlan, port uint16) (net.Conn, string, string, error) {
	if len(plan.addresses) == 0 {
		return nil, "", "", fmt.Errorf("no dial address resolved")
	}
	portText := strconv.Itoa(int(port))
	var lastErr error
	attempts := 0
	for _, address := range plan.addresses {
		attempts++
		target := net.JoinHostPort(address, portText)
		conn, err := r.dial(ctx, "tcp", target)
		if err == nil {
			r.recordDialSuccess(plan.cacheKey, address)
			if attempts == 1 {
				return conn, target, "tcp connect ok", nil
			}
			return conn, target, fmt.Sprintf("tcp connect ok after %d attempts", attempts), nil
		}
		r.recordDialFailure(plan.cacheKey, address)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("tcp connect failed")
	}
	return nil, "", "", lastErr
}

func runTLSDiagnostic(ctx context.Context, conn net.Conn, req protocol.DiagnosticRequest) (protocol.DiagnosticStepResult, error) {
	serverName := strings.TrimSpace(req.TLSServerName)
	if serverName == "" && net.ParseIP(strings.TrimSpace(req.Host)) == nil {
		serverName = req.Host
	}
	tlsConn := tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: req.TLSSkipVerify,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return protocol.DiagnosticStepResult{
			TLSServerName: serverName,
		}, err
	}
	state := tlsConn.ConnectionState()
	return protocol.DiagnosticStepResult{
		TLSServerName:  serverName,
		TLSVersion:     tlsVersionLabel(state.Version),
		TLSCipherSuite: tls.CipherSuiteName(state.CipherSuite),
		TLSPeerNames:   certificatePeerNames(state.PeerCertificates),
		Message:        "tls handshake ok",
	}, nil
}

func certificatePeerNames(certs []*x509.Certificate) []string {
	if len(certs) == 0 || certs[0] == nil {
		return nil
	}
	peer := certs[0]
	names := make([]string, 0, 1+len(peer.DNSNames)+len(peer.IPAddresses))
	if cn := strings.TrimSpace(peer.Subject.CommonName); cn != "" {
		names = append(names, cn)
	}
	names = append(names, peer.DNSNames...)
	for _, ip := range peer.IPAddresses {
		if ip == nil {
			continue
		}
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func tlsVersionLabel(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func durationMillis(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	ms := d / time.Millisecond
	if ms < 0 {
		return 0
	}
	if ms > time.Duration(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(ms)
}
