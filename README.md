# nix — Linux Scheduler Forensics

A single-file, standard-library-only Go CLI for inspecting Linux scheduler execution time, runnable wait time, context switches, disk I/O counters, process identities, and cgroup v2 CPU accounting. Designed for Fedora and RHEL-family Linux distributions.

## Build

```bash
go build -trimpath -ldflags='-s -w' -o nix nix.go
./nix -interval 2
```

Requires Go and Linux with `/proc` mounted. No third-party Go packages are needed. Some metrics may require additional permissions or kernel scheduler accounting support.

## Usage

```bash
./nix -interval 1 -watch
./nix -interval 2 -threads -wide
./nix -sort wait -limit 30
./nix -sort io -filter postgres
./nix -json -interval 1 > sample.json
./nix -json -watch -interval 2 > samples.jsonl
./nix -json -exited -interval 1
./nix -no-color -interval 1
./nix -color -interval 1
```

## Metrics

- CPU execution time and runnable queue delay from `/proc/PID/schedstat`, when available.
- CPU percentage expressed as one logical CPU's wall-clock capacity; it may exceed 100% for multithreaded processes.
- Scheduler wait percentage is runnable delay divided by sample duration, **not** blocked sleep time. It can exceed 100% for aggregated multithreaded processes.
- Physical I/O bytes from `/proc/PID/io` and context-switch counters from `/proc/PID/status`.
- Scheduler policy, nice, last CPU, CPU affinity, and wait channel.
- Per-process cgroup v2 membership and current observer cgroup CPU usage, throttling, periods, and quota when accessible.
- Process identities observed only in the first or second sample are counted as exited or started. Short-lived processes occurring entirely between samples cannot be detected.

## Output

The terminal view groups CPU activity, scheduler contention, disk I/O, and context-switch activity. JSON reports contain the full set of comparable records and sample metadata. ANSI output is automatically disabled for redirected output or when `NO_COLOR` is set; use `-color` to force it.

## Important limitations

- `-threads` adds individual thread rows alongside process-level rows. **Do not sum these rows:** Linux process-level scheduling and I/O accounting may overlap with thread-level values.
- A process must exist in both snapshots to yield a rate. PID, TGID, and start ticks form its identity to guard against PID reuse.
- Counter availability is tracked explicitly; inaccessible counters are not silently treated as valid zero values for rate calculation.
- Collection happens sequentially and can take time; process activity and the reported snapshot interval are approximations rather than synchronized kernel-wide measurements.
- The cgroup CPU summary describes the cgroup containing the observer, not a sum of all process cgroups.
- `/proc` permissions, `hidepid`, containers, and kernel configuration affect coverage.

## License

GPL-3.0-or-later. Add your preferred copyright notice when publishing.
