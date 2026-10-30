// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
)

const (
	// MAX_DATAPOINT is the limit in bytes of any data field. The limit
	// is used to prevent sending data upstream that is too large for the
	// server to store. The limit is specified in bytes.
	// TODO: needed to increase the size for vulnerability reports
	// we need to size down the vulnerability reports with just current cves and advisories
	MAX_DATAPOINT = 2 * (1 << 20)
)

type DatapointCollector interface {
	SinkData([]*llx.RawResult)
}

type Collector interface {
	DatapointCollector
}

type BufferedCollector struct {
	results   map[string]*llx.RawResult
	lock      sync.Mutex
	collector *ResultCollector
	duration  time.Duration
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

type BufferedCollectorOpt func(*BufferedCollector)

func NewBufferedCollector(collector *ResultCollector, opts ...BufferedCollectorOpt) *BufferedCollector {
	c := &BufferedCollector{
		results:   map[string]*llx.RawResult{},
		duration:  5 * time.Second,
		collector: collector,
		stopChan:  make(chan struct{}),
	}
	c.run()
	return c
}

func (c *BufferedCollector) run() {
	c.wg.Go(func() {

		done := false
		results := []*llx.RawResult{}
		for {

			c.lock.Lock()
			for _, rr := range c.results {
				results = append(results, rr)
			}
			for k := range c.results {
				delete(c.results, k)
			}

			c.lock.Unlock()

			if len(results) > 0 || done {
				c.collector.SinkData(results, done)
			}

			results = results[:0]

			if done {
				return
			}

			// TODO: we should only use one timer
			timer := time.NewTimer(c.duration)
			select {
			case <-c.stopChan:
				done = true
			case <-timer.C:
			}
			timer.Stop()
		}
	})
}

func (c *BufferedCollector) FlushAndStop() {
	close(c.stopChan)
	c.wg.Wait()
}

func (c *BufferedCollector) SinkData(results []*llx.RawResult) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, rr := range results {
		c.results[rr.CodeID] = rr
	}
}

type ResultCollector struct {
	assetMrn string
}

func (c *ResultCollector) toResult(rr *llx.RawResult) *llx.Result {
	v := rr.Result()
	if v.Data.Size() > MAX_DATAPOINT {
		log.Warn().
			Str("asset", c.assetMrn).
			Str("id", rr.CodeID).
			Msg("executor.scoresheet> not storing datafield because it is too large")

		v = &llx.Result{
			Error:  "datafield was removed because it is too large",
			CodeId: v.CodeId,
		}
	}
	return v
}

func (c *ResultCollector) SinkData(results []*llx.RawResult, isDone bool) {
	if len(results) == 0 {
		return
	}
	resultsToSend := make(map[string]*llx.Result, len(results))
	for _, rr := range results {
		resultsToSend[rr.CodeID] = c.toResult(rr)
	}

	log.Debug().Msg("Sending datapoints")
	// TODO
}

type FuncCollector struct {
	SinkDataFunc func(results []*llx.RawResult)
}

func (c *FuncCollector) SinkData(results []*llx.RawResult) {
	if len(results) == 0 || c.SinkDataFunc == nil {
		return
	}
	c.SinkDataFunc(results)
}
