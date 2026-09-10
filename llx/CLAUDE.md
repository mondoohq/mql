# Claude AI Context for `llx/`

Rules for the bytecode VM and its builtin functions (array, dict, and comparator operations). The root `CLAUDE.md` still applies.

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
- **A null operand of `&&` or `||` is falsy** (ADR 040 part 4): `null && anything` is `false`, `null || x` is `x`, and `null == null` is still `true`. Before v14, `null && null` evaluated to `true` and `null || true` to `false`; nine providers carried regression tests for the first of those. Keep this contract when touching the boolean builtins.
