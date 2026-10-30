# auditctl -l output

`auditctl -l` output for the rules in `rules-loaded.txt`, which were loaded
into the kernel of an arm64 Linux 7.0 machine (the Docker Desktop VM, from a
privileged container in the host PID namespace) and then listed by the
auditctl of other distributions' audit packages.

- `arm64.txt`: identical from auditctl 2.8.1 (Amazon Linux 2), 2.8.5 (Ubuntu
  20.04), 3.0.9 (Debian 12), 3.1.2 (Ubuntu 24.04, Rocky Linux 8), 3.1.5 (Rocky
  Linux 9, Amazon Linux 2023), 4.0.1 (Alpine 3.20) and 4.1.1 (Fedora 41).
- `arm64-numeric-compat.txt`: auditctl 3.0.6 (openSUSE Leap 15.6) and 4.0.2
  (openSUSE Tumbleweed), whose syscall tables lack 32-bit ARM, so the
  `arch=b32` rule is listed as `arch=0x40000028` with syscall numbers.
