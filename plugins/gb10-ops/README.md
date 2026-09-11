# gb10-ops

Guards and samplers for keeping an NVIDIA DGX Spark (GB10) alive under sustained load.

This box has two failure modes that a normal GPU server does not have, and the
standard tools are blind to both of them. Everything here exists because one of
them actually happened.

The write-up behind this repo, in Traditional Chinese:
[Day 28｜NVIDIA DGX Spark GB10 維運篇](https://ithelp.ithome.com.tw/articles/10409085),
from the series 128GB 統一記憶體的三十天：DGX Spark 地端 LLM 與生成式 AI 部署實戰.
It covers how each threshold here was arrived at, and what the two incidents
looked like while they were happening.

## The two failure modes

**Thermal soak, not peak temperature.** The chassis is small and the air path is
short. A long render or a fine-tune run raises the temperature of the whole
enclosure, and what kills the machine is time spent hot, continuously. One run on
2026-09-01 sat at zone 88 C or above for 417 unbroken seconds and the box cut
power at the firmware level: no kernel log, no shutdown sequence, nothing to read
afterwards. The same workload from a cold start finished normally.

**Unified memory with no safety net.** There is no OOM exception and the OOM
killer never fires. The machine simply stops responding to everything except
ping. On 2026-09-06 the kernel logged its first `NV_ERR_NO_MEMORY` at 23:12:53
and the last line of any kind at 23:56:00, so the warning arrived **43 minutes**
before the machine was gone.

## What is in here

| Path | What it does |
|---|---|
| `guards/gb10-host-guard.py` | Host level memory guard. Watches `MemAvailable` and the `NV_ERR_NO_MEMORY` rate, finds the offending process, terminates it before the whole box goes down. |
| `guards/thermal-run.py` | Wraps any long running local command in a cooling gate plus a thermal watchdog. Runs the child in its own process group and kills the group on a soak violation. |
| `guards/thermal-guard-http.py` | Same idea for servers that cannot be interrupted mid job (ComfyUI, vLLM-Omni). Aborts over HTTP instead of by signal. |
| `samplers/hw-sample.py` | Samples temperature, power and memory to fsync'd JSONL. Also drops a `HOT` flag file that a driver script can check between jobs. |
| `bench/load-decode.py` | Drives sustained decode against an OpenAI compatible endpoint, for measuring power under load rather than at idle. |
| `bench/summarize-samples.py` | Turns a sampler JSONL into one row of numbers, with the head and tail of the window trimmed. |
| `examples/train-guarded.sh` | How to put a fine-tune run behind the gate and the watchdog. |

## Why a host level guard and not a container memory limit

This is the part that surprised me, so it is worth stating plainly.

With a 79 GiB model resident and the host reporting 113 GiB used, the serving
container's own accounting looked like this:

```
cgroup memory.current   11 GiB
cgroup memory.peak      37 GiB
sum of RSS in container  4 GiB
host used              113 GiB
```

The missing 100 GiB is unified memory allocated through the NVIDIA driver, and
**neither the memory cgroup nor RSS can see it**. So `docker run --memory` limits
something that is not the thing that fills this machine, and it will not save you
from the livelock.

Exactly one tool sees it:

```
$ nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv
pid, process_name, used_gpu_memory [MiB]
2065247, VLLM::Worker_TP0, 102843 MiB
```

Note that the same `nvidia-smi` reports `memory.total` as `[N/A]` on this
platform because the pool is unified. Per process `used_memory` still works, and
that is what the guard uses to pick a target.

## Thresholds, and why you should recalibrate them

Every number below came from measurement on one machine. Treat them as a worked
example, not as defaults to copy.

| Threshold | Value | Where it came from |
|---|---|---|
| Soak budget | 240 s at zone >= 88 C | The fatal run soaked for 417 s. 240 s fires three minutes before that point. |
| Controlled abort | 330 s | Past this, a controlled abort costs less than the risk of an uncontrolled power cut. |
| Cooling gate | GPU <= 55 C before start | Two runs of identical work: starting with the chassis 8 C cooler was the difference between finishing and being aborted. |
| MemAvailable warning | 6 GiB | Normal steady state on this box is 7.85 GiB free, and a full 46 minute cluster restart never went below 6.91 GiB. |
| MemAvailable action | 3 GiB | The livelock reached 0.20 GiB and an earlier near miss reached 2 GiB. Both would fire. |
| NVRM rate | 5 lines in 60 s | The livelock produced 24 lines in 21 seconds. A single line is far too noisy: this box has logged 6,697 of them since July. |

Every one of these is a command line flag on the tool that uses it, so
recalibrating means changing an argument, not editing a script.

The obvious threshold is often wrong. "Alert below 8 GiB free" would have been
red continuously during normal service on this machine.

## Reading the machine

Three measurements that are not where you would expect them:

- **Memory: read `/proc/meminfo`.** NVML reports N/A for unified memory, nvtop
  shows a blank memory column, and any dashboard showing "used" is actively
  misleading here. During the 43 minutes before the livelock, "used" sat steady
  at 29.6 percent while `MemAvailable` was 0.16 GiB.
- **Chassis temperature: read `/sys/class/thermal/thermal_zone*/temp` and take
  the maximum.** There is no GPU hwmon on this platform. GPU die temperature
  comes from `nvidia-smi` instead.
- **Power: `nvidia-smi --query-gpu=power.draw` works, and nothing else does.**
  Power limits, module power and GPU memory power all report N/A. There are no
  `power*_input` files under hwmon, no INA driver bound, and
  `/sys/class/power_supply/` is empty. That reading covers the GPU rail only, not
  the wall.

## Install

No root required. Python 3 standard library only, plus `nvidia-smi` and
`journalctl` on `PATH`.

```bash
git clone https://github.com/ivanusto/gb10-ops.git ~/gb10-ops
mkdir -p ~/bin
install -m755 ~/gb10-ops/guards/gb10-host-guard.py ~/gb10-ops/guards/thermal-run.py ~/bin/

# Dry run first. It logs what it would kill without killing anything.
gb10-host-guard.py --dry-run

# Then leave it running, and bring it back after a reboot.
nohup setsid gb10-host-guard.py >/dev/null 2>>~/gb10-host-guard.err &
( crontab -l; echo "@reboot /usr/bin/python3 $HOME/bin/gb10-host-guard.py >/dev/null 2>>$HOME/gb10-host-guard.err" ) | crontab -
```

A systemd user unit is the tidier option but only if lingering is enabled for
your account. With `Linger=no` a user unit does not survive logout, which is
why the line above uses cron.

Putting a long job behind the gate and the watchdog:

```bash
thermal-run.py --cool 55 --soak-zone 88 --soak-seconds 240 -- ./train.py run 4 1536 2
```

Exit code 75 means the watchdog aborted the job. Any other code is the child's own.

## Notes

`pkill -f` and `pgrep -f` do not appear anywhere in this repo on purpose. Both
match on the full command line, which includes the shell that invoked them, and
that is a good way to kill your own session while trying to clean up. The guard
only signals PIDs that `nvidia-smi` named, and the wrapper only signals the
process group it created itself.

Both guards sync every log line to disk. The whole point is that the failures
here take the machine down without a shutdown sequence, so anything still sitting
in a buffer is lost.

## License

MIT. See `LICENSE`.

## Status

Written for one two node GB10 setup and verified there. The mechanisms are
general, the numbers are not. If you run this on other hardware, start with
`--dry-run` and recalibrate against your own idle and steady state first.
