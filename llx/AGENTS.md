# Claude AI Context for `llx/`

Rules for the bytecode VM and its builtin functions (array, dict, and comparator operations). The root `AGENTS.md` still applies.

## Builtin function invariants

- **Never mutate slices or maps obtained from `arg.Value` or `bind.Value`.** They reference shared runtime data: the runtime caches resolved values and may hand the same `RawData` pointer to multiple callers, so an in-place mutation corrupts the value for every later use. Copy before modifying:
  ```go
  // WRONG: mutates the argument's backing array in-place
  filters := arg.Value.([]any)
  filters = append(filters[0:j], filters[j+1:]...)  // destroys arg.Value for future callers

  // CORRECT: copy first, then mutate the copy
  argFilters := arg.Value.([]any)
  filters := make([]any, len(argFilters))
  copy(filters, argFilters)
  filters = append(filters[0:j], filters[j+1:]...)
  ```
- **A `panic` in a builtin or comparator crashes the entire scan**, not one query: the executor runs blocks in goroutines, so the panic is unrecoverable. Guard every type assertion on `arg.Value`/`bind.Value` with comma-ok (`x, ok := v.([]any)`) or a `== nil` check; never use the bare `v.(T)` form on runtime data.
- **A classified failure is an `*llx.Error`** (ADR 046), built with `llx.Forbidden(err, llx.WithPermissions("ec2:DescribeInstances"))` and its siblings. Read the classification with `llx.KindOf(err)` or `errors.Is(err, llx.ErrForbidden)`, never by matching the message: both unwrap, which is the whole reason the kind is a type. The kind crosses a process boundary as an `ErrorDetail` (`DataRes.error_detail`, `Result.error_detail`), so anything that rebuilds an error from a wire message must go through `llx.ErrorFromDetail`. A bare `errors.New(res.Error)` silently drops the kind and degrades that path to pre-ADR behavior.
- **A null operand of `&&` or `||` is falsy** (ADR 040 part 4): `null && anything` is `false`, `null || x` is `x`, and `null == null` is still `true`. Before v14, `null && null` evaluated to `true` and `null || true` to `false`; nine providers carried regression tests for the first of those. Keep this contract when touching the boolean builtins.
