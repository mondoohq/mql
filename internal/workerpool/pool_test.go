// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package workerpool_test

import (
	"errors"
	"testing"
	"time"

	"math/rand"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/internal/workerpool"
)

func TestPoolSubmitAndRetrieveResult(t *testing.T) {
	pool := workerpool.New[int](2)
	pool.Start()
	defer pool.Close()

	task := func() (int, error) {
		return 42, nil
	}

	// no results
	assert.Empty(t, pool.GetResults())

	// submit a request
	pool.Submit(task)

	// wait for the request to process
	pool.Wait()

	// should have one result
	results := pool.GetResults()
	if assert.Len(t, results, 1) {
		assert.Equal(t, 42, results[0].Value)
		// without errors
		assert.NoError(t, results[0].Error)
	}
}

func TestPoolHandleErrors(t *testing.T) {
	pool := workerpool.New[int](5)
	pool.Start()
	defer pool.Close()

	// submit a task that will return an error
	task := func() (int, error) {
		return 0, errors.New("task error")
	}
	pool.Submit(task)

	// Wait for collector to process the results
	pool.Wait()

	errs := pool.GetErrors()
	if assert.Len(t, errs, 1) {
		assert.Equal(t, errs[0].Error(), "task error")
	}
}

func TestPoolMultipleTasksWithEmptyResultsAndNilErrors(t *testing.T) {
	type test struct {
		data int
	}
	pool := workerpool.New[*test](5)
	pool.Start()
	defer pool.Close()

	tasks := []workerpool.Task[*test]{
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return &test{1}, nil },
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return nil, nil },
		func() (*test, error) { return nil, nil },
	}

	for _, task := range tasks {
		pool.Submit(task)
	}

	// Wait for error collector to process
	pool.Wait()

	assert.Empty(t, pool.GetErrors())
}

func TestPoolMultipleTasksWithErrors(t *testing.T) {
	type test struct {
		data int
	}
	pool := workerpool.New[*test](5)
	pool.Start()
	defer pool.Close()

	tasks := []workerpool.Task[*test]{
		func() (*test, error) { return &test{1}, nil },
		func() (*test, error) { return &test{2}, nil },
		func() (*test, error) {
			return nil, errors.New("task error")
		},
		func() (*test, error) { return &test{3}, nil },
	}

	for _, task := range tasks {
		pool.Submit(task)
	}

	// Wait for error collector to process
	pool.Wait()

	// Access results together
	assert.ElementsMatch(t,
		[]workerpool.Result[*test]{
			{&test{1}, nil},
			{&test{2}, nil},
			{&test{3}, nil},
			{nil, errors.New("task error")},
		},
		pool.GetResults(),
	)

	// You can also access values and errors directly
	assert.ElementsMatch(t,
		[]*test{nil, &test{1}, &test{2}, &test{3}},
		pool.GetValues(),
	)
	assert.ElementsMatch(t,
		[]error{errors.New("task error")},
		pool.GetErrors(),
	)
}

func TestPoolHandlesNilTasks(t *testing.T) {
	pool := workerpool.New[int](2)
	pool.Start()
	defer pool.Close()

	var nilTask workerpool.Task[int]
	pool.Submit(nilTask)

	pool.Wait()

	assert.Empty(t, pool.GetErrors())
	assert.Empty(t, pool.GetValues())
}

func TestPoolProcessing(t *testing.T) {
	pool := workerpool.New[int](2)
	pool.Start()
	defer pool.Close()

	task := func() (int, error) {
		time.Sleep(50 * time.Millisecond)
		return 10, nil
	}

	pool.Submit(task)

	// should be processing
	assert.True(t, pool.Processing())

	// wait
	pool.Wait()

	// read values
	assert.Equal(t, []int{10}, pool.GetValues())

	// should not longer be processing
	assert.False(t, pool.Processing())
}

func TestPoolClosesGracefully(t *testing.T) {
	pool := workerpool.New[int](1)
	pool.Start()

	task := func() (int, error) {
		time.Sleep(100 * time.Millisecond)
		return 42, nil
	}

	pool.Submit(task)

	pool.Close()

	// Ensure no panic occurs and channels are closed
	assert.PanicsWithError(t, "send on closed channel", func() {
		pool.Submit(task)
	})
}

func TestPoolWithManyTasks(t *testing.T) {
	// 30k requests with a pool of 100 workers
	// should be around 15 seconds
	requestCount := 30000
	pool := workerpool.New[int](100)
	pool.Start()
	defer pool.Close()

	task := func() (int, error) {
		random := rand.Intn(100)
		time.Sleep(time.Duration(random) * time.Millisecond)
		return random, nil
	}

	for range requestCount {
		pool.Submit(task)
	}

	// should be processing
	assert.True(t, pool.Processing())

	// wait
	pool.Wait()

	// read results
	assert.Equal(t, requestCount, len(pool.GetResults()))

	// should not longer be processing
	assert.False(t, pool.Processing())
}
