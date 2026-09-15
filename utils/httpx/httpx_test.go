// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package httpx

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingReadCloser blocks on Read until Close is called, then returns err.
type blockingReadCloser struct {
	done chan struct{}
	err  error
	once sync.Once
}

func (b *blockingReadCloser) Read(p []byte) (int, error) {
	<-b.done
	return 0, b.err
}

func (b *blockingReadCloser) Close() error {
	b.once.Do(func() { close(b.done) })
	return nil
}

// slowReadCloser returns data in small chunks with a time.Sleep between each Read.
// Inside a synctest bubble the sleeps use fake time, so tests are instant.
type slowReadCloser struct {
	data  []byte
	pos   int
	chunk int
	delay time.Duration
}

func (s *slowReadCloser) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	time.Sleep(s.delay)
	end := min(s.pos+s.chunk, len(s.data))
	n := copy(p, s.data[s.pos:end])
	s.pos += n
	return n, nil
}

func (s *slowReadCloser) Close() error { return nil }

func TestIdleTimeoutReader_NormalRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		data := []byte("hello world provider data")
		body := io.NopCloser(bytes.NewReader(data))

		itr := NewIdleTimeoutReader(body, 2*time.Minute)
		defer itr.Close()

		got, err := io.ReadAll(itr)
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})
}

func TestIdleTimeoutReader_StalledReadTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		blocker := &blockingReadCloser{
			done: make(chan struct{}),
			err:  io.EOF,
		}

		// Use realistic default timeout — fake time makes this instant
		itr := NewIdleTimeoutReader(blocker, 2*time.Minute)
		defer itr.Close()

		_, err := io.ReadAll(itr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "download stalled")
		assert.Contains(t, err.Error(), "MONDOO_DOWNLOAD_TIMEOUT")
	})
}

func TestIdleTimeoutReader_SlowButActiveSucceeds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		data := bytes.Repeat([]byte("x"), 100)
		slow := &slowReadCloser{
			data:  data,
			chunk: 10,
			delay: 30 * time.Second, // 30s between chunks, well under 2m timeout
		}

		itr := NewIdleTimeoutReader(slow, 2*time.Minute)
		defer itr.Close()

		got, err := io.ReadAll(itr)
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})
}

func TestIdleTimeoutReader_CloseStopsTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		blocker := &blockingReadCloser{
			done: make(chan struct{}),
			err:  io.EOF,
		}

		itr := NewIdleTimeoutReader(blocker, 1*time.Hour)
		require.NoError(t, itr.Close())
		assert.False(t, itr.timedOut.Load())
	})
}

func TestIdleTimeoutReader_LargePayload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		data := []byte(strings.Repeat("abcdefghij", 100_000))
		body := io.NopCloser(bytes.NewReader(data))

		itr := NewIdleTimeoutReader(body, 2*time.Minute)
		defer itr.Close()

		got, err := io.ReadAll(itr)
		require.NoError(t, err)
		assert.Equal(t, len(data), len(got))
	})
}

// DownloadTimeout tests don't involve timers — no synctest needed.

func TestDownloadTimeout_Default(t *testing.T) {
	t.Setenv(EnvDownloadTimeout, "")
	assert.Equal(t, DefaultDownloadTimeout, DownloadTimeout())
}

func TestDownloadTimeout_CustomValue(t *testing.T) {
	t.Setenv(EnvDownloadTimeout, "5m")
	assert.Equal(t, 5*time.Minute, DownloadTimeout())
}

func TestDownloadTimeout_InvalidFallsBackToDefault(t *testing.T) {
	t.Setenv(EnvDownloadTimeout, "not-a-duration")
	assert.Equal(t, DefaultDownloadTimeout, DownloadTimeout())
}

func TestDownloadTimeout_NegativeFallsBackToDefault(t *testing.T) {
	t.Setenv(EnvDownloadTimeout, "-5s")
	assert.Equal(t, DefaultDownloadTimeout, DownloadTimeout())
}

// closeCountingBody returns data on every Read, even after Close, and counts
// the Close calls, which is how a body that was closed by the idle timer yet
// still delivers a buffered chunk looks to IdleTimeoutReader.
type closeCountingBody struct {
	closes atomic.Int32
}

func (b *closeCountingBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, nil
}

func (b *closeCountingBody) Close() error {
	b.closes.Add(1)
	return nil
}

func TestIdleTimeoutReader_ClosesBodyOnce(t *testing.T) {
	t.Run("data after the timer fired does not re-arm it", func(t *testing.T) {
		body := &closeCountingBody{}
		itr := NewIdleTimeoutReader(body, 10*time.Millisecond)
		time.Sleep(50 * time.Millisecond) // timer fires, closes the body once
		n, err := itr.Read(make([]byte, 4))
		require.NoError(t, err) // the body still had a chunk; no error to report yet
		assert.Equal(t, 1, n)
		time.Sleep(50 * time.Millisecond) // a re-armed timer would close again here
		require.NoError(t, itr.Close())
		assert.Equal(t, int32(1), body.closes.Load())
	})

	t.Run("close and timer racing close the body once", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			body := &closeCountingBody{}
			itr := NewIdleTimeoutReader(body, time.Millisecond)
			time.Sleep(time.Millisecond)
			_ = itr.Close()
			time.Sleep(2 * time.Millisecond)
			assert.Equal(t, int32(1), body.closes.Load())
		}
	})
}
