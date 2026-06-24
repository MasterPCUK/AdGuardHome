package dhcpd

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/dhcpsvc"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/require"
)

// testTimeout is a common timeout for tests.
const testTimeout = 1 * time.Second

// testLogger is a logger used in tests.
var testLogger = slogutil.NewDiscardLogger()

type testDHCPServer struct {
	startErrs  chan error
	startCalls chan struct{}
}

// type check
var _ DHCPServer = (*testDHCPServer)(nil)

func newTestDHCPServer(startErrs ...error) (srv *testDHCPServer) {
	srv = &testDHCPServer{
		startErrs:  make(chan error, len(startErrs)),
		startCalls: make(chan struct{}, len(startErrs)+2),
	}

	for _, err := range startErrs {
		srv.startErrs <- err
	}

	return srv
}

// Start implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) Start(_ context.Context) (err error) {
	srv.startCalls <- struct{}{}

	select {
	case err = <-srv.startErrs:
		return err
	default:
		return nil
	}
}

// Stop implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) Stop() (err error) { return nil }

// ResetLeases implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) ResetLeases(_ []*dhcpsvc.Lease) (err error) { return nil }

// GetLeases implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) GetLeases(_ GetLeasesFlags) (leases []*dhcpsvc.Lease) { return nil }

// AddStaticLease implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) AddStaticLease(_ *dhcpsvc.Lease) (err error) { return nil }

// RemoveStaticLease implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) RemoveStaticLease(_ *dhcpsvc.Lease) (err error) { return nil }

// UpdateStaticLease implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) UpdateStaticLease(_ *dhcpsvc.Lease) (err error) { return nil }

// FindMACbyIP implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) FindMACbyIP(_ netip.Addr) (mac net.HardwareAddr) { return nil }

// HostByIP implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) HostByIP(_ netip.Addr) (host string) { return "" }

// IPByHost implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) IPByHost(_ string) (ip netip.Addr) { return netip.Addr{} }

// WriteDiskConfig4 implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) WriteDiskConfig4(_ *V4ServerConf) {}

// WriteDiskConfig6 implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) WriteDiskConfig6(_ *V6ServerConf) {}

// getLeasesRef implements the [DHCPServer] interface for *testDHCPServer.
func (srv *testDHCPServer) getLeasesRef() (leases []*dhcpsvc.Lease) { return nil }

func TestServerStart_retriesUntilStarted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	srv4 := newTestDHCPServer(errNoIfaceIPAddrs, nil)
	srv6 := newTestDHCPServer()
	s := &server{
		srv4:              srv4,
		srv6:              srv6,
		startRetryIvl:     10 * time.Millisecond,
		startRetryTimeout: testTimeout,
		conf: &ServerConfig{
			Logger: testLogger,
		},
	}

	require.NoError(t, s.Start(ctx))
	requireStartCalls(t, srv4.startCalls, 2)
	requireNoStartRetry(t, s)
}

func TestServerStop_stopsStartRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	srv4 := newTestDHCPServer(errNoIfaceIPAddrs)
	srv6 := newTestDHCPServer()
	s := &server{
		srv4:              srv4,
		srv6:              srv6,
		startRetryIvl:     testTimeout,
		startRetryTimeout: testTimeout,
		conf: &ServerConfig{
			Logger: testLogger,
		},
	}

	require.NoError(t, s.Start(ctx))
	requireStartCalls(t, srv4.startCalls, 1)
	require.NoError(t, s.Stop())
	requireNoStartRetry(t, s)
}

func requireStartCalls(tb testing.TB, calls <-chan struct{}, n int) {
	tb.Helper()

	for range n {
		select {
		case <-calls:
			// Go on.
		case <-time.After(testTimeout):
			require.FailNow(tb, "not enough start calls")
		}
	}
}

func requireNoStartRetry(tb testing.TB, s *server) {
	tb.Helper()

	deadline := time.NewTimer(testTimeout)
	defer deadline.Stop()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		s.startMu.Lock()
		stopped := s.startRetryCancel == nil
		s.startMu.Unlock()

		if stopped {
			return
		}

		select {
		case <-deadline.C:
			require.FailNow(tb, "start retry did not stop")
		case <-ticker.C:
			// Go on.
		}
	}
}
