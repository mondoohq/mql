// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

const (
	// ExecutionQueryNodeType represents a node that will execute
	// a query. It can be notified by datapoint nodes, representing
	// its dependant properties
	ExecutionQueryNodeType NodeType = "execution_query"
	// DatapointNodeType represents a node that is a datapoint/entrypoint.
	// These nodes are implicitly notified when results are received from
	// the executor threads. They also have edges from execution query nodes,
	// however these just connect the execution and reporting nodes in the graph.
	// When triggered by an execution query, the result will be a noop. These nodes
	// typically notify execution query nodes with properties, reporting query
	// nodes to calculate a query score, and reporting job nodes the calculate
	// data collection completion.
	DatapointNodeType NodeType = "datapoint"
	// ReportingJobNodeType represent scores that needed to be collected. This
	// information is sourced from the resolved policy. Nodes of this type are
	// notified by datapoints to indicate collection of data, reporting query
	// nodes to be notified of query scores, and other reporting job nodes to
	// be notified of scores of dependant reporting jobs
	ReportingJobNodeType NodeType = "reporting_job"
	// DatapointCollectorNodeType represents a sink for datapoints in the graph.
	// There is only one of these nodes in the graph, and it can only be notified
	// by datapoint nodes
	DatapointCollectorNodeType NodeType = "datapoint_collector"
	// CollectionFinisherNodeType represents a node that collects datapoints. It is
	// used to notify of completion when all the expected datapoints have been received.
	// It is different from the datapoint collector node in that it always has the lowest
	// priority, so all other work is guaranteed to complete before it says things are done
	CollectionFinisherNodeType NodeType = "collection_finisher"

	DatapointCollectorID NodeID = "__datapoint_collector__"
	CollectionFinisherID NodeID = "__collection_finisher__"
)

type executionQueryProperty struct {
	name     string
	checksum string
	value    *llx.Result
	resolved bool
}

func (p *executionQueryProperty) Resolve(value *llx.Result) {
	p.value = value
	p.resolved = true
}

func (p *executionQueryProperty) IsResolved() bool {
	return p.resolved
}

type queryRunState int

const (
	notReadyQueryNotReady queryRunState = iota
	readyQueryRunState
	executedQueryRunState
)

// ExecutionQueryNodeData represents a node of type ExecutionQueryNodeType
type ExecutionQueryNodeData struct {
	queryID    string
	codeBundle *llx.CodeBundle

	invalidated        bool
	requiredProperties map[string]*executionQueryProperty
	runState           queryRunState
	runQueue           chan<- runQueueItem
}

func (nodeData *ExecutionQueryNodeData) initialize() {
	nodeData.updateRunState()
	if nodeData.runState == readyQueryRunState {
		nodeData.invalidated = true
	}
}

// consume saves any received data that matches any the required properties
func (nodeData *ExecutionQueryNodeData) consume(from NodeID, data *envelope) {
	if nodeData.runState == executedQueryRunState {
		// Nothing can change once the query has been marked as executed
		return
	}

	if len(nodeData.requiredProperties) == 0 {
		nodeData.invalidated = true
	}

	if data.res != nil {
		for _, p := range nodeData.requiredProperties {
			// Find the property with the matching checksum
			if p.checksum == data.res.CodeID {
				// Save the value of the property
				p.Resolve(data.res.Result())
				// invalidate the node for recalculation
				nodeData.invalidated = true
			}
		}
	}
}

// recalculate checks if all required properties are satisfied. Once
// all have been received, the query is queued for execution
func (nodeData *ExecutionQueryNodeData) recalculate() *envelope {
	if !nodeData.invalidated {
		// Nothing can change once the query has been marked as executed
		return nil
	}

	// Update the run state so we know if the state changed to
	// runnable
	nodeData.updateRunState()
	nodeData.invalidated = false

	if nodeData.runState == readyQueryRunState {
		nodeData.run()
	}

	// An empty envelope notifies the parent. These nodes always point at
	// Datapoint nodes. The datapoint nodes don't need this message, and
	// it actually makes more work for the datapoint node. The reason to
	// send it is to uphold the contract of if something changes, we push
	// a message through the graph. And in this case, something did
	// technically change
	return &envelope{}
}

// run sends this query to be run to the executor queue
// this should only be called when the query is runnable (
// all properties needed are available)
func (nodeData *ExecutionQueryNodeData) run() {
	var props map[string]*llx.Result

	if len(nodeData.requiredProperties) > 0 {
		props = make(map[string]*llx.Result)
		for _, p := range nodeData.requiredProperties {
			props[p.name] = p.value
		}
	}

	nodeData.runState = executedQueryRunState

	nodeData.runQueue <- runQueueItem{
		codeBundle: nodeData.codeBundle,
		props:      props,
	}
}

// updateRunState sets the query to runnable if all the
// required properties needed have been received
func (d *ExecutionQueryNodeData) updateRunState() {
	if d.runState == readyQueryRunState {
		return
	}

	runnable := true

	for _, p := range d.requiredProperties {
		runnable = runnable && p.IsResolved()
	}

	if runnable {
		d.runState = readyQueryRunState
	} else {
		d.runState = notReadyQueryNotReady
	}
}

// DatapointNodeData is the data for queries of type DatapointNodeType.
type DatapointNodeData struct {
	expectedType *string
	isReported   bool
	invalidated  bool
	res          *llx.RawResult
}

func (nodeData *DatapointNodeData) initialize() {
	if nodeData.res != nil {
		nodeData.set(nodeData.res)
	}
}

// consume saves the result of the datapoint.
func (nodeData *DatapointNodeData) consume(from NodeID, data *envelope) {
	if nodeData.isReported {
		// No change detection happens. If a datapoint is reported once, that is the value
		// we will use.
		return
	}
	if data == nil || data.res == nil {
		// This can be triggered with no data by the execution query nodes. These
		// messages are not the ones we care about
		return
	}

	nodeData.set(data.res)
}

func (nodeData *DatapointNodeData) set(res *llx.RawResult) {
	nodeData.invalidated = true
	nodeData.isReported = true

	if nodeData.expectedType == nil || types.Type(*nodeData.expectedType) == types.Unset ||
		res.Data.Type == types.Nil || res.Data.Type == types.Type(*nodeData.expectedType) ||
		res.Data.Error != nil {
		nodeData.res = res
	} else {
		nodeData.res = res.CastResult(types.Type(*nodeData.expectedType)).RawResultV2()
	}
}

// recalculate passes on the datapoint's result if its available
func (nodeData *DatapointNodeData) recalculate() *envelope {
	if !nodeData.invalidated {
		return nil
	}

	nodeData.invalidated = false

	return &envelope{
		res: nodeData.res,
	}
}

// CollectionFinisherNodeData represents the node of type CollectionFinisherNodeType
// It keeps track of the datapoints that have yet to report back
type CollectionFinisherNodeData struct {
	progressReporter ProgressReporter
	totalDatapoints  int

	remainingDatapoints map[NodeID]struct{}
	doneChan            chan struct{}
	invalidated         bool
}

func (nodeData *CollectionFinisherNodeData) initialize() {
	if len(nodeData.remainingDatapoints) == 0 {
		nodeData.invalidated = true
	}
}

// consume marks the received datapoints as finished
func (nodeData *CollectionFinisherNodeData) consume(from NodeID, data *envelope) {
	if len(nodeData.remainingDatapoints) == 0 {
		return
	}
	log.Debug().Msgf("%s finished", from)
	delete(nodeData.remainingDatapoints, from)
	nodeData.invalidated = true
}

// recalculate closes the completion channel if all the data has been received
func (nodeData *CollectionFinisherNodeData) recalculate() *envelope {
	if !nodeData.invalidated {
		return nil
	}
	nodeData.progressReporter.Progress(nodeData.totalDatapoints-len(nodeData.remainingDatapoints), nodeData.totalDatapoints)
	nodeData.invalidated = false
	if len(nodeData.remainingDatapoints) == 0 {
		log.Debug().Msg("graph has received all datapoints")
		close(nodeData.doneChan)
	}
	return nil
}

// DatapointCollectorNodeData is the data for nodes of type DatapointCollectorNodeType
type DatapointCollectorNodeData struct {
	collectors  []DatapointCollector
	unreported  map[string]*llx.RawResult
	invalidated bool
}

func (nodeData *DatapointCollectorNodeData) initialize() {
	if len(nodeData.unreported) > 0 {
		nodeData.invalidated = true
	}
}

// consume collects datapoints
func (nodeData *DatapointCollectorNodeData) consume(from NodeID, data *envelope) {
	if data.res != nil {
		nodeData.unreported[data.res.CodeID] = data.res
		nodeData.invalidated = true
	}
}

// recalculate passes the newly collected datapoints to the configured collectors
func (nodeData *DatapointCollectorNodeData) recalculate() *envelope {
	if !nodeData.invalidated {
		return nil
	}
	nodeData.invalidated = false
	arr := make([]*llx.RawResult, len(nodeData.unreported))
	i := 0
	for _, rr := range nodeData.unreported {
		arr[i] = rr
		i++
	}
	for _, dc := range nodeData.collectors {
		dc.SinkData(arr)
	}
	for k := range nodeData.unreported {
		delete(nodeData.unreported, k)
	}
	return nil
}
