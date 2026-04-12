package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

const (
	defaultDiagnosticTimeout = 10 * time.Second
	maxDiagnosticTimeout     = 60 * time.Second
)

type diagnosticAPIRequest struct {
	AgentID       string `json:"agentId,omitempty"`
	GroupID       string `json:"groupId,omitempty"`
	ProfileID     string `json:"profileId,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	TLSEnabled    bool   `json:"tlsEnabled"`
	TLSServerName string `json:"tlsServerName,omitempty"`
	TLSSkipVerify bool   `json:"tlsSkipVerify,omitempty"`
	TimeoutMs     int    `json:"timeoutMs,omitempty"`
}

type diagnosticAPIResponse struct {
	Mode            string                    `json:"mode,omitempty"`
	AgentID         string                    `json:"agentId,omitempty"`
	AgentName       string                    `json:"agentName,omitempty"`
	GroupID         string                    `json:"groupId,omitempty"`
	GroupName       string                    `json:"groupName,omitempty"`
	ProfileID       string                    `json:"profileId,omitempty"`
	ProfileName     string                    `json:"profileName,omitempty"`
	Host            string                    `json:"host"`
	Port            int                       `json:"port"`
	OverrideAddress string                    `json:"overrideAddress,omitempty"`
	ReasonCode      string                    `json:"reasonCode,omitempty"`
	Reason          string                    `json:"reason,omitempty"`
	SelectedStatus  string                    `json:"selectedStatus,omitempty"`
	CandidateCount  int                       `json:"candidateCount,omitempty"`
	StartedAt       time.Time                 `json:"startedAt,omitempty"`
	FinishedAt      time.Time                 `json:"finishedAt,omitempty"`
	DurationMillis  int64                     `json:"durationMillis,omitempty"`
	Success         bool                      `json:"success"`
	Error           string                    `json:"error,omitempty"`
	Steps           []diagnosticAPIStepResult `json:"steps,omitempty"`
}

type diagnosticAPIStepResult struct {
	Step             string   `json:"step"`
	Success          bool     `json:"success"`
	DurationMillis   uint32   `json:"durationMillis,omitempty"`
	Message          string   `json:"message,omitempty"`
	ResolutionSource string   `json:"resolutionSource,omitempty"`
	Addresses        []string `json:"addresses,omitempty"`
	SelectedAddress  string   `json:"selectedAddress,omitempty"`
	TLSServerName    string   `json:"tlsServerName,omitempty"`
	TLSVersion       string   `json:"tlsVersion,omitempty"`
	TLSCipherSuite   string   `json:"tlsCipherSuite,omitempty"`
	TLSPeerNames     []string `json:"tlsPeerNames,omitempty"`
}

type diagnosticSelection struct {
	Mode            string
	Host            string
	Port            int
	AgentID         string
	AgentName       string
	GroupID         string
	GroupName       string
	ProfileID       string
	ProfileName     string
	OverrideAddress string
	ReasonCode      string
	Reason          string
	SelectedStatus  string
	CandidateCount  int
	Session         *relayAgentSession
}

type diagnosticAPIError struct {
	status  int
	message string
}

func (e *diagnosticAPIError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func (s *relayAgentSession) runDiagnostic(ctx context.Context, req protocol.DiagnosticRequest) (protocol.DiagnosticResponse, error) {
	if s == nil {
		return protocol.DiagnosticResponse{}, errors.New("agent session unavailable")
	}
	if req.RequestID == 0 {
		req.RequestID = s.server.nextStreamID()
	}
	waiter := make(chan protocol.DiagnosticResponse, 1)
	if err := s.storeDiagnosticWaiter(req.RequestID, waiter); err != nil {
		return protocol.DiagnosticResponse{}, err
	}
	defer s.popDiagnosticWaiter(req.RequestID)

	packet, err := protocol.EncodeDiagnosticRequestPacket(req)
	if err != nil {
		return protocol.DiagnosticResponse{}, err
	}
	if err := s.sendPacket(packet); err != nil {
		return protocol.DiagnosticResponse{}, err
	}

	select {
	case resp := <-waiter:
		return resp, nil
	case <-ctx.Done():
		return protocol.DiagnosticResponse{}, ctx.Err()
	case <-s.shutdown:
		return protocol.DiagnosticResponse{}, errSessionClosed
	}
}

func (s *relayAgentSession) storeDiagnosticWaiter(requestID uint64, waiter chan protocol.DiagnosticResponse) error {
	s.diagnosticsMu.Lock()
	defer s.diagnosticsMu.Unlock()
	if s.diagnostics == nil {
		s.diagnostics = make(map[uint64]chan protocol.DiagnosticResponse)
	}
	if _, exists := s.diagnostics[requestID]; exists {
		return fmt.Errorf("diagnostic request %d already pending", requestID)
	}
	s.diagnostics[requestID] = waiter
	return nil
}

func (s *relayAgentSession) popDiagnosticWaiter(requestID uint64) chan protocol.DiagnosticResponse {
	s.diagnosticsMu.Lock()
	defer s.diagnosticsMu.Unlock()
	if s.diagnostics == nil {
		return nil
	}
	waiter := s.diagnostics[requestID]
	delete(s.diagnostics, requestID)
	return waiter
}

func (s *relayServer) handleDiagnosticsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload diagnosticAPIRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}

	payload.AgentID = strings.TrimSpace(payload.AgentID)
	payload.GroupID = strings.TrimSpace(payload.GroupID)
	payload.ProfileID = strings.TrimSpace(payload.ProfileID)
	payload.Host = strings.TrimSpace(payload.Host)
	payload.TLSServerName = strings.TrimSpace(payload.TLSServerName)

	selection, err := s.resolveDiagnosticSelection(r.Context(), payload)
	if err != nil {
		if selection.Host != "" || selection.AgentID != "" || selection.GroupID != "" || selection.ProfileID != "" {
			s.recordDiagnosticOutcome(r, selection, diagnosticAPIResponse{}, err)
		}
		http.Error(w, err.Error(), diagnosticHTTPStatus(err))
		return
	}

	timeout := effectiveDiagnosticTimeout(payload.TimeoutMs, s.dialTimeout())
	req := protocol.DiagnosticRequest{
		RequestID:       s.nextStreamID(),
		Host:            selection.Host,
		Port:            uint16(selection.Port),
		OverrideAddress: selection.OverrideAddress,
		TLSEnabled:      payload.TLSEnabled,
		TLSServerName:   payload.TLSServerName,
		TLSSkipVerify:   payload.TLSSkipVerify,
		TimeoutMillis:   uint32(timeout / time.Millisecond),
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout+2*time.Second)
	defer cancel()
	resp, err := selection.Session.runDiagnostic(ctx, req)
	if err != nil {
		s.recordDestinationCircuitOutcome(selection.GroupID, selection.GroupName, net.JoinHostPort(selection.Host, strconv.Itoa(selection.Port)), err)
		s.recordDiagnosticOutcome(r, selection, diagnosticAPIResponse{}, err)
		http.Error(w, err.Error(), diagnosticHTTPStatus(err))
		return
	}

	apiResp := buildDiagnosticAPIResponse(selection, resp)
	if apiResp.Success {
		s.recordDestinationCircuitOutcome(selection.GroupID, selection.GroupName, net.JoinHostPort(selection.Host, strconv.Itoa(selection.Port)), nil)
	} else {
		s.recordDestinationCircuitOutcome(selection.GroupID, selection.GroupName, net.JoinHostPort(selection.Host, strconv.Itoa(selection.Port)), errors.New(firstNonEmpty(apiResp.Error, apiResp.Reason, "diagnostic failed")))
	}
	s.recordDiagnosticOutcome(r, selection, apiResp, nil)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(apiResp); err != nil {
		s.logger.Warn("diagnostic response encode failed", "error", err)
	}
}

func (s *relayServer) resolveDiagnosticSelection(ctx context.Context, payload diagnosticAPIRequest) (diagnosticSelection, error) {
	selection := diagnosticSelection{}
	if payload.AgentID != "" && (payload.GroupID != "" || payload.ProfileID != "") {
		return selection, &diagnosticAPIError{
			status:  http.StatusBadRequest,
			message: "agentId cannot be combined with groupId or profileId",
		}
	}

	switch {
	case payload.ProfileID != "":
		return s.resolveDiagnosticProfileSelection(ctx, payload)
	case payload.GroupID != "":
		return s.resolveDiagnosticGroupSelection(ctx, payload)
	case payload.AgentID != "":
		return s.resolveDiagnosticAgentSelection(payload)
	default:
		return selection, &diagnosticAPIError{
			status:  http.StatusBadRequest,
			message: "one of agentId, groupId or profileId is required",
		}
	}
}

func (s *relayServer) resolveDiagnosticAgentSelection(payload diagnosticAPIRequest) (diagnosticSelection, error) {
	host, port, err := normalizeDiagnosticTarget(payload.Host, payload.Port)
	if err != nil {
		return diagnosticSelection{
			Mode: "agent",
			Host: host,
			Port: port,
		}, err
	}
	session, ok := s.lookupAgent(payload.AgentID)
	if !ok {
		return diagnosticSelection{
				Mode:    "agent",
				Host:    host,
				Port:    port,
				AgentID: payload.AgentID,
			}, &diagnosticAPIError{
				status:  http.StatusNotFound,
				message: "agent not connected",
			}
	}
	selection := diagnosticSelection{
		Mode:           "agent",
		Host:           host,
		Port:           port,
		AgentID:        payload.AgentID,
		AgentName:      session.displayName(),
		ReasonCode:     "diagnostic_agent_direct",
		Reason:         "explicit agent selection",
		SelectedStatus: session.snapshot().Status,
		CandidateCount: 1,
		Session:        session,
	}
	selection.OverrideAddress = s.diagnosticOverrideAddress(host)
	return selection, nil
}

func (s *relayServer) resolveDiagnosticGroupSelection(ctx context.Context, payload diagnosticAPIRequest) (diagnosticSelection, error) {
	host, port, err := normalizeDiagnosticTarget(payload.Host, payload.Port)
	if err != nil {
		return diagnosticSelection{
			Mode:    "group",
			Host:    host,
			Port:    port,
			GroupID: payload.GroupID,
		}, err
	}
	if s.control == nil {
		return diagnosticSelection{
				Mode:    "group",
				Host:    host,
				Port:    port,
				GroupID: payload.GroupID,
			}, &diagnosticAPIError{
				status:  http.StatusServiceUnavailable,
				message: "control plane unavailable",
			}
	}
	group, found, err := s.control.GetAgentGroup(ctx, payload.GroupID)
	if err != nil {
		return diagnosticSelection{}, err
	}
	if !found {
		return diagnosticSelection{
				Mode:    "group",
				Host:    host,
				Port:    port,
				GroupID: payload.GroupID,
			}, &diagnosticAPIError{
				status:  http.StatusNotFound,
				message: "group not found",
			}
	}
	candidate := userRouteCandidate{
		GroupID:    group.ID,
		GroupName:  group.Name,
		ReasonCode: "diagnostic_group_auto",
		Reason:     fmt.Sprintf("diagnostic auto-routed through group %q", group.Name),
		Priority:   1,
	}
	selection, err := s.selectDiagnosticGroupCandidate(ctx, candidate, host, port)
	if err != nil {
		selection.Mode = "group"
		return selection, err
	}
	selection.Mode = "group"
	return selection, nil
}

func (s *relayServer) resolveDiagnosticProfileSelection(ctx context.Context, payload diagnosticAPIRequest) (diagnosticSelection, error) {
	selection := diagnosticSelection{
		Mode:      "profile",
		ProfileID: payload.ProfileID,
		GroupID:   payload.GroupID,
	}
	if s.control == nil {
		return selection, &diagnosticAPIError{
			status:  http.StatusServiceUnavailable,
			message: "control plane unavailable",
		}
	}
	profile, found, err := s.control.GetDestinationProfile(ctx, payload.ProfileID)
	if err != nil {
		return selection, err
	}
	if !found {
		return selection, &diagnosticAPIError{
			status:  http.StatusNotFound,
			message: "profile not found",
		}
	}
	selection.ProfileID = profile.ID
	selection.ProfileName = profile.Name
	selection.Host = profile.Host
	selection.Port = profile.Port

	if payload.Host != "" && !strings.EqualFold(payload.Host, profile.Host) {
		return selection, &diagnosticAPIError{
			status:  http.StatusBadRequest,
			message: "host conflicts with selected profile",
		}
	}
	if payload.Port > 0 && payload.Port != profile.Port {
		return selection, &diagnosticAPIError{
			status:  http.StatusBadRequest,
			message: "port conflicts with selected profile",
		}
	}

	groupID := payload.GroupID
	if groupID == "" {
		groupID = profile.DefaultGroupID
	}
	if groupID == "" {
		return selection, &diagnosticAPIError{
			status:  http.StatusBadRequest,
			message: "profile has no default group; supply groupId explicitly",
		}
	}
	group, found, err := s.control.GetAgentGroup(ctx, groupID)
	if err != nil {
		return selection, err
	}
	if !found {
		return selection, &diagnosticAPIError{
			status:  http.StatusNotFound,
			message: "group not found",
		}
	}
	candidate := userRouteCandidate{
		GroupID:     group.ID,
		GroupName:   group.Name,
		ProfileID:   profile.ID,
		ProfileName: profile.Name,
		ReasonCode:  "diagnostic_profile_auto",
		Reason:      fmt.Sprintf("diagnostic profile %q auto-routed through group %q", profile.Name, group.Name),
		Priority:    0,
	}
	selection, err = s.selectDiagnosticGroupCandidate(ctx, candidate, profile.Host, profile.Port)
	if err != nil {
		selection.Mode = "profile"
		return selection, err
	}
	selection.Mode = "profile"
	return selection, nil
}

func (s *relayServer) selectDiagnosticGroupCandidate(ctx context.Context, candidate userRouteCandidate, host string, port int) (diagnosticSelection, error) {
	selection := diagnosticSelection{
		Host:        host,
		Port:        port,
		GroupID:     candidate.GroupID,
		GroupName:   candidate.GroupName,
		ProfileID:   candidate.ProfileID,
		ProfileName: candidate.ProfileName,
		ReasonCode:  candidate.ReasonCode,
		Reason:      candidate.Reason,
	}
	groupSelection, err := s.selectAgentForGroupWithOptions(ctx, candidate, host, port, true)
	if err != nil {
		return selection, err
	}
	selection.AgentID = groupSelection.Membership.AgentID
	selection.AgentName = groupSelection.agentName()
	selection.GroupID = groupSelection.GroupID
	selection.GroupName = groupSelection.GroupName
	selection.ProfileID = groupSelection.ProfileID
	selection.ProfileName = groupSelection.ProfileName
	selection.ReasonCode = groupSelection.ReasonCode
	selection.Reason = groupSelection.Reason
	selection.SelectedStatus = groupSelection.Snapshot.Status
	selection.CandidateCount = groupSelection.CandidateCount
	selection.Session = groupSelection.Session
	selection.OverrideAddress = s.diagnosticOverrideAddress(host)
	return selection, nil
}

func normalizeDiagnosticTarget(host string, port int) (string, int, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", port, &diagnosticAPIError{
			status:  http.StatusBadRequest,
			message: "host is required",
		}
	}
	if port <= 0 || port > 65535 {
		return host, port, &diagnosticAPIError{
			status:  http.StatusBadRequest,
			message: "port must be between 1 and 65535",
		}
	}
	return host, port, nil
}

func buildDiagnosticAPIResponse(selection diagnosticSelection, resp protocol.DiagnosticResponse) diagnosticAPIResponse {
	apiResp := diagnosticAPIResponse{
		Mode:            selection.Mode,
		AgentID:         selection.AgentID,
		AgentName:       selection.AgentName,
		GroupID:         selection.GroupID,
		GroupName:       selection.GroupName,
		ProfileID:       selection.ProfileID,
		ProfileName:     selection.ProfileName,
		Host:            selection.Host,
		Port:            selection.Port,
		OverrideAddress: selection.OverrideAddress,
		ReasonCode:      selection.ReasonCode,
		Reason:          selection.Reason,
		SelectedStatus:  selection.SelectedStatus,
		CandidateCount:  selection.CandidateCount,
		Error:           resp.Error,
		Success:         resp.Error == "",
		Steps:           make([]diagnosticAPIStepResult, 0, len(resp.Steps)),
	}
	if resp.StartedAt > 0 {
		apiResp.StartedAt = time.Unix(0, resp.StartedAt).UTC()
	}
	if resp.FinishedAt > 0 {
		apiResp.FinishedAt = time.Unix(0, resp.FinishedAt).UTC()
	}
	if resp.FinishedAt > resp.StartedAt && resp.StartedAt > 0 {
		apiResp.DurationMillis = int64(time.Unix(0, resp.FinishedAt).Sub(time.Unix(0, resp.StartedAt)) / time.Millisecond)
	}
	for _, step := range resp.Steps {
		apiResp.Steps = append(apiResp.Steps, diagnosticAPIStepResult{
			Step:             step.Step,
			Success:          step.Success,
			DurationMillis:   step.DurationMillis,
			Message:          step.Message,
			ResolutionSource: step.ResolutionSource,
			Addresses:        step.Addresses,
			SelectedAddress:  step.SelectedAddress,
			TLSServerName:    step.TLSServerName,
			TLSVersion:       step.TLSVersion,
			TLSCipherSuite:   step.TLSCipherSuite,
			TLSPeerNames:     step.TLSPeerNames,
		})
		if !step.Success {
			apiResp.Success = false
		}
	}
	return apiResp
}

func (s *relayServer) recordDiagnosticOutcome(r *http.Request, selection diagnosticSelection, resp diagnosticAPIResponse, err error) {
	if s == nil {
		return
	}
	event := statusDiagnosticEvent{
		Timestamp:       time.Now(),
		Mode:            selection.Mode,
		Host:            firstNonEmpty(resp.Host, selection.Host),
		Port:            firstNonZero(resp.Port, selection.Port),
		AgentID:         firstNonEmpty(resp.AgentID, selection.AgentID),
		AgentName:       firstNonEmpty(resp.AgentName, selection.AgentName),
		GroupID:         firstNonEmpty(resp.GroupID, selection.GroupID),
		GroupName:       firstNonEmpty(resp.GroupName, selection.GroupName),
		ProfileID:       firstNonEmpty(resp.ProfileID, selection.ProfileID),
		ProfileName:     firstNonEmpty(resp.ProfileName, selection.ProfileName),
		OverrideAddress: firstNonEmpty(resp.OverrideAddress, selection.OverrideAddress),
		ReasonCode:      firstNonEmpty(resp.ReasonCode, selection.ReasonCode),
		Message:         firstNonEmpty(resp.Reason, selection.Reason),
		SelectedStatus:  firstNonEmpty(resp.SelectedStatus, selection.SelectedStatus),
		CandidateCount:  firstNonZero(resp.CandidateCount, selection.CandidateCount),
		StartedAt:       resp.StartedAt,
		FinishedAt:      resp.FinishedAt,
		DurationMillis:  resp.DurationMillis,
	}
	if event.Host != "" && event.Port > 0 {
		event.Target = net.JoinHostPort(event.Host, strconv.Itoa(event.Port))
	}
	if len(resp.Steps) > 0 {
		event.Steps = make([]statusDiagnosticStep, 0, len(resp.Steps))
		for _, step := range resp.Steps {
			event.Steps = append(event.Steps, statusDiagnosticStep{
				Step:             step.Step,
				Success:          step.Success,
				DurationMillis:   step.DurationMillis,
				Message:          step.Message,
				ResolutionSource: step.ResolutionSource,
				Addresses:        step.Addresses,
				SelectedAddress:  step.SelectedAddress,
				TLSServerName:    step.TLSServerName,
				TLSVersion:       step.TLSVersion,
				TLSCipherSuite:   step.TLSCipherSuite,
				TLSPeerNames:     step.TLSPeerNames,
			})
		}
	}
	if err != nil {
		event.Outcome = "failed"
		event.Message = err.Error()
		switch typed := err.(type) {
		case *routeError:
			if typed.reasonCode != "" {
				event.ReasonCode = typed.reasonCode
			}
		case *diagnosticAPIError:
			if event.ReasonCode == "" {
				event.ReasonCode = "diagnostic_request_invalid"
			}
		default:
			if errors.Is(err, context.DeadlineExceeded) {
				event.ReasonCode = "diagnostic_timeout"
			} else if errors.Is(err, errSessionClosed) {
				event.ReasonCode = "diagnostic_agent_disconnected"
			} else if event.ReasonCode == "" {
				event.ReasonCode = "diagnostic_failed"
			}
		}
	} else {
		if resp.Success {
			event.Outcome = "success"
		} else {
			event.Outcome = "failed"
			if resp.Error != "" {
				event.Message = resp.Error
			}
		}
		if event.ReasonCode == "" {
			event.ReasonCode = "diagnostic_completed"
		}
	}
	if s.diagnosticRuns != nil {
		s.diagnosticRuns.add(event)
	}
	s.recordDashboardAudit(r, controlplane.AuditEvent{
		Category:     "diagnostic",
		Action:       "run",
		ResourceType: "diagnostic",
		ResourceID:   event.Target,
		ResourceName: event.Target,
		Outcome:      event.Outcome,
		Message:      event.Message,
		Metadata: auditMetadata(
			"mode", event.Mode,
			"host", event.Host,
			"port", strconv.Itoa(event.Port),
			"agentId", event.AgentID,
			"groupId", event.GroupID,
			"profileId", event.ProfileID,
			"reasonCode", event.ReasonCode,
			"selectedStatus", event.SelectedStatus,
			"candidateCount", strconv.Itoa(event.CandidateCount),
			"overrideAddress", event.OverrideAddress,
		),
	})
}

func (s *relayAgentSession) displayName() string {
	if name := strings.TrimSpace(s.identification); name != "" {
		return name
	}
	return s.id
}

func (s *relayServer) diagnosticOverrideAddress(host string) string {
	override, ok := s.lookupDNSOverride(host)
	if !ok {
		return ""
	}
	return override.Address
}

func effectiveDiagnosticTimeout(requested int, dialTimeout time.Duration) time.Duration {
	timeout := dialTimeout
	if timeout <= 0 {
		timeout = defaultDiagnosticTimeout
	}
	if requested > 0 {
		timeout = time.Duration(requested) * time.Millisecond
	}
	if timeout <= 0 {
		timeout = defaultDiagnosticTimeout
	}
	if timeout > maxDiagnosticTimeout {
		return maxDiagnosticTimeout
	}
	return timeout
}

func diagnosticHTTPStatus(err error) int {
	switch typed := err.(type) {
	case *diagnosticAPIError:
		if typed.status > 0 {
			return typed.status
		}
	case *routeError:
		return routeHTTPStatus(err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	if errors.Is(err, errSessionClosed) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
