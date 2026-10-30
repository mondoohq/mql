// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func TestDatapointNode(t *testing.T) {
	newNodeData := func() *DatapointNodeData {
		return &DatapointNodeData{}
	}
	t.Run("initialize/recalculate", func(t *testing.T) {
		t.Run("does not recalculate if data is not provided", func(t *testing.T) {
			nodeData := newNodeData()

			nodeData.initialize()
			data := nodeData.recalculate()

			assert.Nil(t, data)
		})

		t.Run("recalculates if data is provided", func(t *testing.T) {
			nodeData := newNodeData()
			nodeData.res = &llx.RawResult{
				CodeID: "checksum",
				Data:   llx.BoolTrue,
			}

			nodeData.initialize()
			data := nodeData.recalculate()

			require.NotNil(t, data)
			require.NotNil(t, data.res)
			assert.Equal(t, "checksum", data.res.CodeID)
			assert.Equal(t, llx.BoolTrue, data.res.Data)
		})

		t.Run("casts if required type is provided", func(t *testing.T) {
			nodeData := newNodeData()
			typ := string(types.Bool)
			nodeData.expectedType = &typ
			nodeData.res = &llx.RawResult{
				CodeID: "checksum",
				Data:   llx.StringData("hello"),
			}

			nodeData.initialize()
			data := nodeData.recalculate()

			require.NotNil(t, data)
			require.NotNil(t, data.res)
			assert.Equal(t, "checksum", data.res.CodeID)
			assert.Equal(t, llx.BoolTrue, data.res.Data)
		})
	})

	t.Run("consume/recalculate", func(t *testing.T) {
		t.Run("ignores nils", func(t *testing.T) {
			nodeData := newNodeData()

			nodeData.initialize()
			nodeData.recalculate()

			nodeData.consume(NodeID("__executor__"), &envelope{})
			data := nodeData.recalculate()
			assert.Nil(t, data)
		})

		t.Run("recalculate when data arrives", func(t *testing.T) {
			nodeData := newNodeData()

			nodeData.initialize()
			nodeData.recalculate()

			nodeData.consume(NodeID("__executor__"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum",
					Data:   llx.BoolTrue,
				},
			})
			data := nodeData.recalculate()

			require.NotNil(t, data)
			require.NotNil(t, data.res)
			assert.Equal(t, "checksum", data.res.CodeID)
			assert.Equal(t, llx.BoolTrue, data.res.Data)
		})

		t.Run("doesn't recalculate multiple times", func(t *testing.T) {
			nodeData := newNodeData()
			nodeData.res = &llx.RawResult{
				CodeID: "checksum",
				Data:   llx.BoolTrue,
			}

			nodeData.initialize()
			data := nodeData.recalculate()
			require.NotNil(t, data)
			assert.NotNil(t, data.res)

			nodeData.consume(NodeID("__executor__"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum",
					Data:   llx.BoolFalse,
				},
			})
			data = nodeData.recalculate()
			assert.Nil(t, data)
		})

		t.Run("casts if required type is provided", func(t *testing.T) {
			nodeData := newNodeData()
			typ := string(types.Bool)
			nodeData.expectedType = &typ

			nodeData.initialize()
			nodeData.recalculate()

			nodeData.consume(NodeID("__executor__"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum",
					Data:   llx.StringData("hello"),
				},
			})
			data := nodeData.recalculate()

			require.NotNil(t, data)
			require.NotNil(t, data.res)
			assert.Equal(t, "checksum", data.res.CodeID)
			assert.Equal(t, llx.BoolTrue, data.res.Data)
		})

		t.Run("skips cast if required type are same", func(t *testing.T) {
			nodeData := newNodeData()
			typ := string(types.String)
			nodeData.expectedType = &typ

			nodeData.initialize()
			nodeData.recalculate()

			resData := llx.StringData("hello")
			nodeData.consume(NodeID("__executor__"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum",
					Data:   resData,
				},
			})
			data := nodeData.recalculate()

			require.NotNil(t, data)
			require.NotNil(t, data.res)
			assert.Equal(t, "checksum", data.res.CodeID)
			assert.Equal(t, resData, data.res.Data)
		})

		t.Run("skips cast if datapoint is error", func(t *testing.T) {
			nodeData := newNodeData()
			typ := string(types.String)
			nodeData.expectedType = &typ

			nodeData.initialize()
			nodeData.recalculate()

			nodeData.consume(NodeID("__executor__"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum",
					Data: &llx.RawData{
						Error: errors.New("error happened"),
					},
				},
			})
			data := nodeData.recalculate()

			require.NotNil(t, data)
			require.NotNil(t, data.res)
			assert.Equal(t, "checksum", data.res.CodeID)
			require.NotNil(t, data.res.Data.Error)
			assert.Equal(t, "error happened", data.res.Data.Error.Error())
			assert.Nil(t, data.res.Data.Value)
		})

		t.Run("skips cast if expected type is unset", func(t *testing.T) {
			nodeData := newNodeData()
			typ := string(types.Unset)
			nodeData.expectedType = &typ

			nodeData.initialize()
			nodeData.recalculate()

			resData := llx.StringData("hello")
			nodeData.consume(NodeID("__executor__"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum",
					Data:   resData,
				},
			})
			data := nodeData.recalculate()

			require.NotNil(t, data)
			require.NotNil(t, data.res)
			assert.Equal(t, "checksum", data.res.CodeID)
			assert.Equal(t, resData, data.res.Data)
		})
	})
}

func TestExecutionQueryNode(t *testing.T) {
	newNodeData := func() (*ExecutionQueryNodeData, chan runQueueItem) {
		q := make(chan runQueueItem, 1)
		data := &ExecutionQueryNodeData{
			queryID:            "testqueryid",
			requiredProperties: map[string]*executionQueryProperty{},
			runState:           notReadyQueryNotReady,
			runQueue:           q,
			codeBundle: &llx.CodeBundle{
				CodeV2: &llx.CodeV2{
					Id: "testqueryid",
				},
			},
		}
		return data, q
	}
	t.Run("initialize/recalculate", func(t *testing.T) {
		t.Run("does not recalculate if dependencies not satisfied", func(t *testing.T) {
			nodeData, q := newNodeData()
			nodeData.requiredProperties = map[string]*executionQueryProperty{
				"prop1": {
					name:     "prop1",
					checksum: "checksum1",
					resolved: false,
				},
			}
			nodeData.initialize()
			data := nodeData.recalculate()
			assert.Nil(t, data)
			select {
			case <-q:
				assert.Fail(t, "not ready for execution")
			default:
			}
		})
		t.Run("recalculates if dependencies are satisfied", func(t *testing.T) {
			nodeData, q := newNodeData()
			nodeData.requiredProperties = map[string]*executionQueryProperty{
				"prop1": {
					name:     "prop1",
					checksum: "checksum1",
					resolved: true,
					value:    llx.BoolFalse.Result(),
				},
				"prop2": {
					name:     "prop2",
					checksum: "checksum1",
					resolved: true,
					value:    llx.BoolFalse.Result(),
				},
			}
			nodeData.initialize()
			data := nodeData.recalculate()
			assert.NotNil(t, data)
			assert.Nil(t, data.res)
			select {
			case item := <-q:
				require.NotNil(t, item.codeBundle)
				assert.Equal(t, "testqueryid", item.codeBundle.CodeV2.Id)
				assert.Contains(t, item.props, "prop1")
			default:
				assert.Fail(t, "expected something to be executed")
			}
		})
	})

	t.Run("consume/recalculate", func(t *testing.T) {
		t.Run("does not recalculate if dependencies not satisfied", func(t *testing.T) {
			nodeData, q := newNodeData()
			nodeData.requiredProperties = map[string]*executionQueryProperty{
				"prop1": {
					name:     "prop1",
					checksum: "checksum1",
				},
				"prop2": {
					name:     "prop2",
					checksum: "checksum2",
				},
			}
			nodeData.initialize()
			data := nodeData.recalculate()
			assert.Nil(t, data)
			nodeData.consume(NodeID("checksum1"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum1",
					Data:   llx.BoolTrue,
				},
			})

			select {
			case <-q:
				assert.Fail(t, "not ready for execution")
			default:
			}
		})
		t.Run("only recalculates once", func(t *testing.T) {
			nodeData, q := newNodeData()
			nodeData.requiredProperties = map[string]*executionQueryProperty{
				"prop1": {
					name:     "prop1",
					checksum: "checksum1",
				},
				"prop2": {
					name:     "prop2",
					checksum: "checksum1",
				},
			}
			nodeData.initialize()
			data := nodeData.recalculate()
			assert.Nil(t, data)
			nodeData.consume(NodeID("checksum1"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum1",
					Data:   llx.BoolTrue,
				},
			})
			data = nodeData.recalculate()
			assert.NotNil(t, data)
			select {
			case <-q:
			default:
				assert.Fail(t, "expected something to be executed")
			}

			nodeData.consume(NodeID("checksum1"), &envelope{
				res: &llx.RawResult{
					CodeID: "checksum1",
					Data:   llx.BoolTrue,
				},
			})
			_ = nodeData.recalculate()
			select {
			case <-q:
				assert.Fail(t, "query should not re-execute")
			default:
			}
		})
		t.Run("recalculates after all dependencies are satisfied", func(t *testing.T) {})
	})
}

func TestCollectionFinisherNode(t *testing.T) {
	newNodeData := func(reporter func(numCompleted int, total int)) *CollectionFinisherNodeData {
		data := &CollectionFinisherNodeData{
			progressReporter: ProgressReporterFunc(reporter),
			doneChan:         make(chan struct{}),
		}
		return data
	}

	results := map[string]*llx.RawResult{
		"codeID1": {
			CodeID: "codeID1",
			Data:   llx.BoolData(true),
		},
	}

	t.Run("initialize/recalculate", func(t *testing.T) {
		t.Run("recalculates if there are no remaining datapoints", func(t *testing.T) {
			nodeData := newNodeData(func(completed int, total int) {
				assert.Equal(t, 0, completed)
				assert.Equal(t, 0, total)
			})

			nodeData.initialize()
			nodeData.recalculate()

			select {
			case _, ok := <-nodeData.doneChan:
				assert.False(t, ok)
			default:
				assert.Fail(t, "expected channel to be closed")
			}
		})
		t.Run("does not recalculate if there are remaining datapoints", func(t *testing.T) {
			nodeData := newNodeData(func(completed int, total int) {
				assert.Fail(t, "should not recalculate")
			})

			nodeData.totalDatapoints = 2
			nodeData.remainingDatapoints = map[string]struct{}{
				"codeID1": {},
				"codeID2": {},
			}

			nodeData.initialize()
			nodeData.recalculate()

			select {
			case <-nodeData.doneChan:
				assert.Fail(t, "expected channel to be open")
			default:
			}
		})
	})

	t.Run("consume/recalculate", func(t *testing.T) {
		t.Run("notifies progress when partially complete", func(t *testing.T) {
			progressCalled := false
			nodeData := newNodeData(func(completed int, total int) {
				progressCalled = true
				assert.Equal(t, 1, completed)
				assert.Equal(t, 2, total)
			})
			nodeData.totalDatapoints = 2
			nodeData.remainingDatapoints = map[string]struct{}{
				"codeID1": {},
				"codeID2": {},
			}
			nodeData.initialize()
			nodeData.consume("codeID1", &envelope{
				res: results["codeID1"],
			})
			nodeData.recalculate()

			assert.True(t, progressCalled)
			select {
			case <-nodeData.doneChan:
				assert.Fail(t, "expected channel to be open")
			default:
			}
		})
		t.Run("notifies progress and signals finish when fully complete", func(t *testing.T) {
			progressCalled := false
			nodeData := newNodeData(func(completed int, total int) {
				progressCalled = true
				assert.Equal(t, 1, completed)
				assert.Equal(t, 1, total)
			})
			nodeData.totalDatapoints = 1
			nodeData.remainingDatapoints = map[string]struct{}{
				"codeID1": {},
			}
			nodeData.initialize()
			nodeData.consume("codeID1", &envelope{
				res: results["codeID1"],
			})
			nodeData.recalculate()

			assert.True(t, progressCalled)
			select {
			case _, ok := <-nodeData.doneChan:
				assert.False(t, ok)
			default:
				assert.Fail(t, "expected channel to be closed")
			}
		})
	})
}

func TestDatapointCollectorNode(t *testing.T) {
	newNodeData := func(collectorFunc func(results []*llx.RawResult)) *DatapointCollectorNodeData {
		data := &DatapointCollectorNodeData{
			unreported: make(map[string]*llx.RawResult),
			collectors: []DatapointCollector{
				&FuncCollector{
					SinkDataFunc: collectorFunc,
				},
			},
		}
		return data
	}

	initExpectedData := func() map[string]*llx.RawResult {
		return map[string]*llx.RawResult{
			"codeID1": {
				CodeID: "codeID1",
				Data:   llx.BoolData(true),
			},
			"codeID2": {
				CodeID: "codeID2",
				Data:   llx.BoolData(false),
			},
		}
	}
	t.Run("initialize/recalculate", func(t *testing.T) {
		t.Run("recalculates if unreported datapoints are available", func(t *testing.T) {
			collected := map[string]int{}
			expectedData := initExpectedData()
			nodeData := newNodeData(func(results []*llx.RawResult) {
				for _, r := range results {
					assert.Equal(t, expectedData[r.CodeID], r)
					collected[r.CodeID] = collected[r.CodeID] + 1
				}
			})

			nodeData.unreported = expectedData

			nodeData.initialize()
			nodeData.recalculate()

			assert.Equal(t, 2, len(collected))
			for _, v := range collected {
				assert.Equal(t, 1, v)
			}
		})

		t.Run("does not recalculate if no unreported data", func(t *testing.T) {
			calls := 0
			nodeData := newNodeData(func(results []*llx.RawResult) {
				calls += 1
			})

			nodeData.initialize()
			nodeData.recalculate()

			assert.Equal(t, 0, calls)
		})
	})

	t.Run("consume/recalculate", func(t *testing.T) {
		t.Run("recalculates if unreported datapoints are available", func(t *testing.T) {
			collected := map[string]int{}
			expectedData := initExpectedData()

			nodeData := newNodeData(func(results []*llx.RawResult) {
				for _, r := range results {
					assert.Equal(t, expectedData[r.CodeID], r)
					collected[r.CodeID] = collected[r.CodeID] + 1
				}
			})

			nodeData.initialize()
			nodeData.consume("codeID1", &envelope{
				res: expectedData["codeID1"],
			})
			nodeData.consume("rjID1", &envelope{
				res: expectedData["codeID2"],
			})
			nodeData.recalculate()

			assert.Equal(t, 2, len(collected))
			for _, v := range collected {
				assert.Equal(t, 1, v)
			}
		})
	})
}
