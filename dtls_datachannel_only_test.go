// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/fingerprint"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/sctp"
	"github.com/pion/webrtc/v4"
	"github.com/stretchr/testify/require"
)

// The peer deliberately uses raw ICE/DTLS/SCTP, not another WebRTC transport:
// two transports with the same SRTP bug can otherwise hide an interop failure.
func TestDTLSDataChannelsOnlyRawPeer(t *testing.T) {
	for _, role := range []webrtc.DTLSRole{webrtc.DTLSRoleClient, webrtc.DTLSRoleServer} {
		t.Run(role.String(), func(t *testing.T) {
			for _, tc := range []struct {
				name             string
				dataOnly         bool
				peerSRTP         bool
				wrongFingerprint bool
			}{
				{name: "DataOnly", dataOnly: true},
				{name: "WrongFingerprint", dataOnly: true, wrongFingerprint: true},
				{name: "DefaultRequiresSRTP"},
				{name: "DefaultWithSRTP", peerSRTP: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					var settings webrtc.SettingEngine
					settings.SetDTLSDataChannelsOnly(tc.dataOnly)
					// An explicit profile must not re-enable SRTP in data-only mode.
					settings.SetSRTPProtectionProfiles(dtls.SRTP_AEAD_AES_128_GCM)
					settings.SetDTLSCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
					settings.SetDTLSConnectContextMaker(func() (context.Context, func()) { return ctx, nil })
					settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
					settings.SetIncludeLoopbackCandidate(true)
					settings.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
					settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
					hellos := make(chan bool, 8)
					recordHello := func(extensions []extension.Extension) {
						found := false
						for _, ext := range extensions {
							found = found || ext.TypeValue() == extension.UseSRTPTypeValue
						}
						select {
						case hellos <- found:
						default:
						}
					}
					settings.SetDTLSClientHelloMessageHook(func(m handshake.MessageClientHello) handshake.Message {
						recordHello(m.Extensions)
						return &m
					})
					settings.SetDTLSServerHelloMessageHook(func(m handshake.MessageServerHello) handshake.Message {
						recordHello(m.Extensions)
						return &m
					})
					api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
					transport, raw, localErr, rawErr := rawDTLSPeer(t, ctx, api, role, tc.peerSRTP, tc.wrongFingerprint)
					if tc.wrongFingerprint || (!tc.dataOnly && !tc.peerSRTP) {
						require.Error(t, localErr)
						require.Equal(t, webrtc.DTLSTransportStateFailed, transport.State())
						return
					}
					require.NoError(t, localErr)
					require.NoError(t, rawErr)
					require.Equal(t, webrtc.DTLSTransportStateConnected, transport.State())
					state, ok := raw.ConnectionState()
					require.True(t, ok)
					require.Equal(t, dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, state.CipherSuiteID)
					_, selected := raw.SelectedSRTPProtectionProfile()
					require.Equal(t, tc.peerSRTP, selected)
					select {
					case advertised := <-hellos:
						require.Equal(t, !tc.dataOnly, advertised, "actual outgoing hello use_srtp")
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					if tc.dataOnly {
						assertDataOnlyMediaRejected(t, api, transport)
					} else {
						// The default still creates and uses a real SRTCP session.
						_, err := transport.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 1}})
						require.NoError(t, err)
					}
					exchangeRawDataChannel(t, ctx, api, transport, raw)
				})
			}
		})
	}
}

func assertDataOnlyMediaRejected(t *testing.T, api *webrtc.API, transport *webrtc.DTLSTransport) {
	t.Helper()
	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "audio", "stream")
	require.NoError(t, err)
	// Checking another API against this transport also prevents cross-API bypass.
	for _, mediaAPI := range []*webrtc.API{api, webrtc.NewAPI()} {
		_, err = mediaAPI.NewRTPSender(track, transport)
		require.ErrorIs(t, err, webrtc.ErrMediaDisabled)
		_, err = mediaAPI.NewRTPReceiver(webrtc.RTPCodecTypeAudio, transport)
		require.ErrorIs(t, err, webrtc.ErrMediaDisabled)
	}
	_, err = transport.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 1}})
	require.ErrorIs(t, err, webrtc.ErrMediaDisabled)
}

// rawDTLSPeer only uses exported APIs. Both sides are restricted to loopback,
// without STUN/TURN, credentials, external networking or application signaling.
func rawDTLSPeer(t *testing.T, ctx context.Context, api *webrtc.API, role webrtc.DTLSRole, peerSRTP, wrongFingerprint bool) (*webrtc.DTLSTransport, *dtls.Conn, error, error) {
	t.Helper()
	gatherer, err := api.NewICEGatherer(webrtc.ICEGatherOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gatherer.Close() })
	localICE := api.NewICETransport(gatherer)
	t.Cleanup(func() { _ = localICE.Stop() })
	transport, err := api.NewDTLSTransport(localICE, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = transport.Stop() })
	agent, err := ice.NewAgentWithOptions(
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost}),
		ice.WithIncludeLoopback(), ice.WithIPFilter(func(ip net.IP) bool { return ip.IsLoopback() }),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = agent.Close() })
	localGathered, rawGathered := make(chan struct{}), make(chan struct{})
	gatherer.OnLocalCandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			close(localGathered)
		}
	})
	require.NoError(t, agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			close(rawGathered)
		}
	}))
	require.NoError(t, gatherer.Gather())
	require.NoError(t, agent.GatherCandidates())
	for _, gathered := range []chan struct{}{localGathered, rawGathered} {
		select {
		case <-gathered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	localCandidates, err := gatherer.GetLocalCandidates()
	require.NoError(t, err)
	require.NotEmpty(t, localCandidates)
	for _, c := range localCandidates {
		rawCandidate, convertErr := c.ToICE()
		require.NoError(t, convertErr)
		require.NoError(t, agent.AddRemoteCandidate(rawCandidate))
	}
	rawCandidates, err := agent.GetLocalCandidates()
	require.NoError(t, err)
	require.NotEmpty(t, rawCandidates)
	for _, c := range rawCandidates {
		require.NoError(t, localICE.AddRemoteCandidate(&webrtc.ICECandidate{
			Foundation: c.Foundation(), Priority: c.Priority(), Address: c.Address(),
			Protocol: webrtc.ICEProtocolUDP, Port: uint16(c.Port()), Typ: webrtc.ICECandidateTypeHost, Component: c.Component(),
		}))
	}
	localParams, err := gatherer.GetLocalParameters()
	require.NoError(t, err)
	ufrag, pwd, err := agent.GetLocalUserCredentials()
	require.NoError(t, err)
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	fp, err := fingerprint.Fingerprint(parsed, crypto.SHA256)
	require.NoError(t, err)
	if wrongFingerprint {
		if fp[0] == '0' {
			fp = "1" + fp[1:]
		} else {
			fp = "0" + fp[1:]
		}
	}
	remoteRole := webrtc.DTLSRoleClient
	if role == webrtc.DTLSRoleClient {
		remoteRole = webrtc.DTLSRoleServer
	}
	localResult := make(chan error, 1)
	go func() {
		iceRole := webrtc.ICERoleControlled
		if startErr := localICE.Start(nil, webrtc.ICEParameters{UsernameFragment: ufrag, Password: pwd}, &iceRole); startErr != nil {
			localResult <- startErr
			return
		}
		localResult <- transport.Start(webrtc.DTLSParameters{Role: remoteRole, Fingerprints: []webrtc.DTLSFingerprint{{Algorithm: "sha-256", Value: fp}}})
	}()
	rawICE, err := agent.Dial(ctx, localParams.UsernameFragment, localParams.Password)
	require.NoError(t, err)
	localDTLSParams, err := transport.GetLocalParameters()
	require.NoError(t, err)
	verifyLocal := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("missing WebRTC certificate")
		}
		parsedCert, parseErr := x509.ParseCertificate(rawCerts[0])
		if parseErr != nil {
			return parseErr
		}
		actual, fingerprintErr := fingerprint.Fingerprint(parsedCert, crypto.SHA256)
		if fingerprintErr != nil {
			return fingerprintErr
		}
		if actual != localDTLSParams.Fingerprints[0].Value {
			return fmt.Errorf("WebRTC certificate fingerprint mismatch")
		}
		return nil
	}
	opts := []dtls.Option{dtls.WithCertificates(cert), dtls.WithInsecureSkipVerify(true), dtls.WithVerifyPeerCertificate(verifyLocal), dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
	if peerSRTP {
		opts = append(opts, dtls.WithSRTPProtectionProfiles(dtls.SRTP_AEAD_AES_128_GCM))
	}
	var raw *dtls.Conn
	if role == webrtc.DTLSRoleClient {
		serverOpts := []dtls.ServerOption{dtls.WithClientAuth(dtls.RequireAnyClientCert)}
		for _, opt := range opts {
			serverOpts = append(serverOpts, opt)
		}
		raw, err = dtls.ServerWithOptions(&connectedPacketConn{Conn: rawICE}, rawICE.RemoteAddr(), serverOpts...)
	} else {
		clientOpts := make([]dtls.ClientOption, 0, len(opts))
		for _, opt := range opts {
			clientOpts = append(clientOpts, opt)
		}
		raw, err = dtls.ClientWithOptions(&connectedPacketConn{Conn: rawICE}, rawICE.RemoteAddr(), clientOpts...)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	rawErr := raw.HandshakeContext(ctx)
	select {
	case localErr := <-localResult:
		return transport, raw, localErr, rawErr
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return nil, nil, ctx.Err(), rawErr
	}
}

type connectedPacketConn struct{ net.Conn }

func (c *connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func exchangeRawDataChannel(t *testing.T, ctx context.Context, api *webrtc.API, transport *webrtc.DTLSTransport, raw *dtls.Conn) {
	t.Helper()
	localSCTP := api.NewSCTPTransport(transport)
	t.Cleanup(func() { _ = localSCTP.Stop() })
	localStarted := make(chan error, 1)
	go func() { localStarted <- localSCTP.StartContext(ctx, localSCTP.GetCapabilities()) }()
	rawSCTP, err := sctp.ClientContext(ctx, sctp.WithNetConn(raw), sctp.WithLoggerFactory(logging.NewDefaultLoggerFactory()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawSCTP.Close() })
	select {
	case err = <-localStarted:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	rawResult := make(chan error, 1)
	go func() {
		channel, acceptErr := datachannel.Accept(rawSCTP, &datachannel.Config{LoggerFactory: logging.NewDefaultLoggerFactory()})
		if acceptErr != nil {
			rawResult <- acceptErr
			return
		}
		buf := make([]byte, 128)
		n, isString, readErr := channel.ReadDataChannel(buf)
		if readErr != nil {
			rawResult <- readErr
			return
		}
		if isString || !bytes.Equal(buf[:n], []byte("encrypted WebRTC to raw")) {
			rawResult <- fmt.Errorf("unexpected WebRTC payload %q", buf[:n])
			return
		}
		_, writeErr := channel.WriteDataChannel([]byte("encrypted raw to WebRTC"), false)
		rawResult <- writeErr
	}()
	id := uint16(0)
	channel, err := api.NewDataChannel(localSCTP, &webrtc.DataChannelParameters{ID: &id, Ordered: true, Label: "raw-dtls-regression"})
	require.NoError(t, err)
	received := make(chan webrtc.DataChannelMessage, 1)
	channel.OnMessage(func(m webrtc.DataChannelMessage) { received <- m })
	opened := make(chan struct{})
	channel.OnOpen(func() { close(opened) })
	select {
	case <-opened:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, channel.Send([]byte("encrypted WebRTC to raw")))
	select {
	case err = <-rawResult:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case m := <-received:
		require.False(t, m.IsString)
		require.Equal(t, []byte("encrypted raw to WebRTC"), m.Data)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
