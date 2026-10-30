// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package workerpool

import (
	"sync"
	"sync/atomic"
	"time"
)

// Represent the tasks that can be sent to the pool.
type Task[R any] func() (result R, err error)

// The result generated from a task.
type Result[R any] struct {
	Value R
	Error error
}

// Pool is a generic pool of workers.
type Pool[R any] struct {
	// The queue where tasks are submitted.
	queueCh chan Task[R]

	// Where workers send the results after a task is executed,
	// the collector then reads them and aggregate them.
	resultsCh chan Result[R]

	// The total number of requests sent.
	requestsSent atomic.Int64

	// Number of workers to spawn.
	workerCount int

	// The list of workers that are listening to the queue.
	workers []*worker[R]

	// A single collector to aggregate results.
	collector[R]

	// used to protect starting the pool multiple times
	once sync.Once
}

// New initializes a new Pool with the provided number of workers. The pool is generic and can
// accept any type of Task that returns the signature `func() (R, error)`.
//
// For example, a Pool[int] will accept Tasks similar to:
//
//	task := func() (int, error) {
//		return 42, nil
//	}
func New[R any](count int) *Pool[R] {
	resultsCh := make(chan Result[R])
	return &Pool[R]{
		queueCh:     make(chan Task[R]),
		resultsCh:   resultsCh,
		workerCount: count,
		collector:   collector[R]{resultsCh: resultsCh},
	}
}

// Start the pool workers and collector. Make sure call `Close()` to clear the pool.
//
//	pool := workerpool.New[int](10)
//	pool.Start()
//	defer pool.Close()
func (p *Pool[R]) Start() {
	p.once.Do(func() {
		for i := 0; i < p.workerCount; i++ {
			w := worker[R]{id: i, queueCh: p.queueCh, resultsCh: p.resultsCh}
			w.start()
			p.workers = append(p.workers, &w)
		}

		p.start()
	})
}

// Submit sends a task to the workers
func (p *Pool[R]) Submit(t Task[R]) {
	if t != nil {
		p.queueCh <- t
		p.requestsSent.Add(1)
	}
}

// GetResults returns the tasks results.
//
// It is recommended to call `Wait()` before reading the results.
func (p *Pool[R]) GetResults() []Result[R] {
	return p.collector.GetResults()
}

// GetValues returns only the values of the pool results
//
// It is recommended to call `Wait()` before reading the results.
func (p *Pool[R]) GetValues() []R {
	return p.collector.GetValues()
}

// GetErrors returns only the errors of the pool results
//
// It is recommended to call `Wait()` before reading the results.
func (p *Pool[R]) GettErrors() []error {
	return p.GetErrors()
}

// Close waits for workers and collector to process all the requests, and then closes
// the task queue channel. After closing the pool, calling `Submit()` will panic.
func (p *Pool[R]) Close() {
	p.Wait()
	close(p.queueCh)
}

// Wait waits until all tasks have been processed.
func (p *Pool[R]) Wait() {
	ticker := time.NewTicker(10 * time.Millisecond)
	for {
		if !p.Processing() {
			return
		}
		<-ticker.C
	}
}

// PendingRequests returns the number of pending requests.
func (p *Pool[R]) PendingRequests() int64 {
	return p.requestsSent.Load() - p.RequestsRead()
}

// Processing return true if tasks are being processed.
func (p *Pool[R]) Processing() bool {
	return p.PendingRequests() != 0
}
