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
	return &recordingLease{
		key:               request.Key,
		owner:             request.Owner,
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

type recordingLease struct {
	key               string
	owner             string
	releaseErr        error
	lostBeforeRelease bool
	done              chan struct{}
	held              bool
}

func (l *recordingLease) Info() coordination.LeaseInfo {
	return coordination.LeaseInfo{Key: l.key, Owner: l.owner, Token: 1, AcquiredAt: time.Unix(1, 0).UTC(), ExpiresAt: time.Unix(11, 0).UTC()}
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
