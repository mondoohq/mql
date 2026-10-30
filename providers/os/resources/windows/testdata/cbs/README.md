Fixtures for providers/os/resources/windows/cbs_test.go, taken from a hotpatched
Windows Server 2025 Azure Edition host (build 26100.33222).

- `*.mum`: servicing manifests copied from `%windir%\servicing\Packages`, named
  after their CBS package key. The RollupFix manifest is trimmed to its header
  (the original is 1.6 MB); it is still well-formed and keeps the `<package>`
  element the reader uses. The HotpatchFix and RollupFix manifests start with a
  UTF-8 BOM, as on the host.
- `packages.json`: the `Package_*` rows of the CBS store (key name, CurrentState,
  manifest identifier and release type, InstallTimeUtc). The two ServicingStack
  rows use the identifiers read from the host; the release type of the 33150 row
  is assumed to match the 33288 manifest.
  `Package_for_RollupFix~...~26100.1742.1.10` (state 64, KB5043080) is superseded and must not
  be reported. Get-HotFix on that host returns exactly KB5120708, KB5120228,
  KB5099536, KB5101372 and KB5120232.
