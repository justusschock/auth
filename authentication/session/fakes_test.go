package session_test

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/justusschock/auth/authentication/session"
	coordination "github.com/justusschock/distributed-coordination"
)

type recordingCoordinator struct {
	mu                sync.Mutex
	acquireErr        error
	releaseErr        error
	lostBeforeRelease bool
	requestLog        []coordination.AcquireRequest
	nextToken         coordination.FencingToken
	held              map[string]bool
	releases          map[string]int
	released          chan struct{} // closed and replaced on every release
}

// isHeld reports whether a lease on key is currently held.
func (c *recordingCoordinator) isHeld(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held[key]
}

func (c *recordingCoordinator) Acquire(ctx context.Context, request coordination.AcquireRequest) (coordination.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestLog = append(c.requestLog, request)
	if c.acquireErr != nil {
		return nil, c.acquireErr
	}
	if c.held == nil {
		c.held = make(map[string]bool)
	}
	if c.releases == nil {
		c.releases = make(map[string]int)
	}
	for c.held[request.Key] {
		if !request.Wait {
			return nil, coordination.ErrLeaseLost
		}
		if c.released == nil {
			c.released = make(chan struct{})
		}
		released := c.released
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			c.mu.Lock()
			return nil, ctx.Err()
		case <-released:
			c.mu.Lock()
		}
	}
	c.nextToken++
	c.held[request.Key] = true
	return &recordingLease{
		coordinator:       c,
		key:               request.Key,
		owner:             request.Owner,
		token:             c.nextToken,
		releaseErr:        c.releaseErr,
		lostBeforeRelease: c.lostBeforeRelease,
		done:              make(chan struct{}),
		held:              true,
	}, nil
}

func (c *recordingCoordinator) requests() []coordination.AcquireRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]coordination.AcquireRequest, len(c.requestLog))
	copy(out, c.requestLog)
	return out
}

func (c *recordingCoordinator) releaseCount(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.releases[key]
}

type recordingLease struct {
	coordinator       *recordingCoordinator
	key               string
	owner             string
	token             coordination.FencingToken
	releaseErr        error
	lostBeforeRelease bool
	done              chan struct{}
	held              bool
}

func (l *recordingLease) Info() coordination.LeaseInfo {
	return coordination.LeaseInfo{Key: l.key, Owner: l.owner, Token: l.token, AcquiredAt: time.Unix(1, 0).UTC(), ExpiresAt: time.Unix(11, 0).UTC()}
}

func (l *recordingLease) Done() <-chan struct{} {
	if l.lostBeforeRelease {
		closeOnce(l.done)
	}
	return l.done
}

func (l *recordingLease) Renew(context.Context, time.Duration) (coordination.LeaseInfo, error) {
	return coordination.LeaseInfo{}, coordination.ErrLeaseLost
}

func (l *recordingLease) Release(context.Context) error {
	l.coordinator.mu.Lock()
	l.coordinator.releases[l.key]++
	if l.releaseErr == nil {
		l.coordinator.held[l.key] = false
		if l.coordinator.released != nil {
			close(l.coordinator.released)
			l.coordinator.released = nil
		}
	}
	l.coordinator.mu.Unlock()
	if l.releaseErr != nil {
		return l.releaseErr
	}
	closeOnce(l.done)
	l.held = false
	return nil
}

func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// observingStore wraps MemoryStore to inject CompareAndSwap failures and to
// record whether Get runs while the session's rotation lease is held.
type observingStore struct {
	*session.MemoryStore
	coordinator *recordingCoordinator

	mu              sync.Mutex
	failNextCAS     error
	getsWithLease   atomic.Int32
	getsWithoutLock atomic.Int32
}

func newObservingStore(coordinator *recordingCoordinator) *observingStore {
	return &observingStore{MemoryStore: session.NewMemoryStore(), coordinator: coordinator}
}

func (s *observingStore) Get(ctx context.Context, id string) (session.Session, error) {
	if s.coordinator != nil && s.coordinator.isHeld("auth/session/"+id) {
		s.getsWithLease.Add(1)
	} else {
		s.getsWithoutLock.Add(1)
	}
	return s.MemoryStore.Get(ctx, id)
}

func (s *observingStore) CompareAndSwap(ctx context.Context, id string, expectedVersion, fence uint64, next session.Session) error {
	s.mu.Lock()
	err := s.failNextCAS
	s.failNextCAS = nil
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.MemoryStore.CompareAndSwap(ctx, id, expectedVersion, fence, next)
}

// failNextCompareAndSwap makes the next CompareAndSwap return err.
func (s *observingStore) failNextCompareAndSwap(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNextCAS = err
}
