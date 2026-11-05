# Performance

This page shows how much SeaBee slows down system calls that reach its hooks,
and how many logs are lost under heavy audit traffic.
The results come from `scripts/benchmark.sh`,
which can be run again on any test machine.

## Method

`scripts/benchmark.sh` runs six
[stress-ng](https://github.com/ColinIanKing/stress-ng) stressors,
each for 20 seconds, 3 times,
and keeps the median bogo operations per second (real time).
Each stressor reaches different SeaBee hooks:

| Stressor | SeaBee hooks |
| --- | --- |
| open | `file_open`, `inode_permission` |
| fork | `task_alloc` |
| exec | `bprm_check_security`, `task_alloc` |
| kill | `task_kill` |
| chmod | `inode_setattr` |
| rename | `inode_rename` |

The stressors run in three modes:

- none: SeaBee is not running
- seabee: SeaBee is running with the default configuration and no policy,
  so every hook runs but objects are unlabeled
- policy: stress-ng is in the scope of a policy
  and works in a directory protected by it,
  so every process and file it creates is labeled

The log loss test loads a policy with `file_write_access: audit` on one file,
then opens that file for writing N times from an unlabeled process.
Each open is logged twice, by `file_open` and by `inode_permission`.
The test counts the audit logs SeaBee prints.

To reproduce, install the release build and a root key, then run the script as root:

```bash
make install-release
make gen-root-key-ci
make install-root-key
sudo apt install stress-ng gcc bc
sudo scripts/benchmark.sh
```

SeaBee must not be running when the script starts.
The script takes about 25 minutes.

## Results

Test system: AWS c7i-flex.large (2 vCPU, Intel Xeon Platinum 8488C),
Ubuntu 24.04, kernel 7.0.0-1014-aws,
SeaBee release build of commit 01ce6c6, stress-ng 0.17.06.

### System call overhead

Median bogo operations per second; the percentage is the change from "none".

| Stressor | none | seabee | policy |
| --- | --- | --- | --- |
| open | 81,330 | 78,241 (-3.8%) | 75,320 (-7.4%) |
| fork | 4,622 | 4,559 (-1.4%) | 4,580 (-0.9%) |
| exec | 521.5 | 511.7 (-1.9%) | 524.8 (+0.6%) |
| kill | 58,931 | 58,545 (-0.7%) | 57,707 (-2.1%) |
| chmod | 483.6 | 483.6 (0.0%) | 483.4 (0.0%) |
| rename | 1,396 | 1,367 (-2.1%) | 1,393 (-0.2%) |

`open` shows the largest cost, since every write open runs two SeaBee hooks.
In the policy mode, `exec` ran faster than with no SeaBee,
so differences of 1 to 2% are within the run-to-run variation of this test system.

### Log loss

SeaBee sends logs to user space through a 256 KB ring buffer.
When the buffer is full, the log is dropped
(`log_buf` in `bpf/include/logging.h`).

| Writes | Delay between writes | Time | Audit logs expected | Audit logs printed | Lost |
| --- | --- | --- | --- | --- | --- |
| 100,000 | none | 0.30 s | 200,000 | 131,295 | 34.4% |
| 1,000,000 | none | 3.09 s | 2,000,000 | 1,330,323 | 33.5% |
| 100,000 | 10 µs | 7.50 s | 200,000 | 200,000 | 0% |

At about 650,000 audit logs per second, a third of the logs are lost.
At about 27,000 per second, none are lost.
