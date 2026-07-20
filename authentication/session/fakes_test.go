package session_test

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	coordination "github.com/justusschock/go-distributed-coordination"
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
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			c.mu.Lock()
			return nil, ctx.Err()
		case <-time.After(time.Millisecond):
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

var _ = atomic.Int32{}
