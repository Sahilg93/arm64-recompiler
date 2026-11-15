#!/usr/bin/env python3
"""Benchmark notepad.exe: the lifted ARM64 build hosted on Wine's unix side
against the original x86-64 program under Wine + Rosetta.

Both variants use the same Wine prefix and the same (x86-64) wineserver, and
are driven by the same probe.exe, so only the notepad process differs.

usage: bench_notepad.py --lifted-dir DIR --host-unix DIR --wine-root DIR
                        --prefix DIR --tools DIR [--runs N] [--json FILE]
  --lifted-dir  folder holding the lifted `notepad` binary, notepad.exe and its DLLs
  --tools       folder holding winwait and probe.exe (see winwait.c, probe.c)
"""
import argparse, json, os, re, statistics, subprocess, sys, tempfile, time
from pathlib import Path


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def wine_output(cmd, **kw):
    """Run a Wine command and return its stdout.

    Wine starts long-lived helpers (wineserver, the desktop process) that inherit
    the command's descriptors, so a pipe would never reach end-of-file: use a file.
    """
    with tempfile.TemporaryFile("w+") as out:
        subprocess.run(cmd, stdout=out, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, **kw)
        out.seek(0)
        return out.read()


class Bench:
    def __init__(self, a):
        self.a = a
        self.wine = str(Path(a.wine_root) / "bin/wine")
        self.server = str(Path(a.wine_root) / "bin/wineserver")
        self.base_env = dict(os.environ, WINEPREFIX=str(a.prefix), WINEDEBUG="-all", MVK_CONFIG_LOG_LEVEL="0")
        lifted = Path(a.lifted_dir)
        self.variants = {
            "lifted": dict(cmd=[str(lifted / "notepad")], cwd=str(lifted), env=dict(
                self.base_env, ARM64_RECOMPILER_WINE_HOST=str(a.host_unix),
                ARM64_RECOMPILER_WINE_EXE=str(lifted / "notepad.exe"),
                WINESERVER=self.server, WINELOADER=self.wine,
                DYLD_FALLBACK_LIBRARY_PATH="/opt/homebrew/lib:/usr/local/lib:/usr/lib")),
            "wine+rosetta": dict(cmd=[self.wine, "notepad.exe"], cwd=str(a.tools), env=self.base_env),
        }

    def stop_server(self):
        wine_output([self.server, "-k"], env=self.base_env)
        wine_output([self.server, "-w"], env=self.base_env)

    def probe(self, *args):
        out = wine_output([self.wine, str(Path(self.a.tools) / "probe.exe"), *args], env=self.base_env,
                          cwd=str(self.a.tools), timeout=600)
        result = {}
        for line in out.replace("\r", "").splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] != "error":
                result[parts[0]] = float(parts[1])
        return result

    @staticmethod
    def cpu_seconds(pid):
        text = sh(["ps", "-o", "time=", "-p", str(pid)]).stdout.strip()
        if not text:
            return None
        parts = [float(p) for p in text.split(":")]
        return sum(p * 60 ** i for i, p in enumerate(reversed(parts)))

    @staticmethod
    def memory(pid):
        rss = sh(["ps", "-o", "rss=", "-p", str(pid)]).stdout.strip()
        foot = re.search(r"phys_footprint:\s*([\d.]+)\s*(\w+)", sh(["footprint", "-p", str(pid)]).stdout)
        scale = {"KB": 1 / 1024, "MB": 1, "GB": 1024}
        return (int(rss) / 1024 if rss else None,
                float(foot[1]) * scale.get(foot[2], 1) if foot else None)

    def run(self, variant, file=None, probe=False, idle=2.0):
        v = self.variants[variant]
        args = [file] if file else []
        row = {"variant": variant}
        start = time.perf_counter()
        usage = tempfile.TemporaryFile("w+")  # /usr/bin/time's report; a file, as in wine_output
        process = subprocess.Popen(["/usr/bin/time", "-l", *v["cmd"], *args], cwd=v["cwd"], env=v["env"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=usage)
        try:
            shown = sh([str(Path(self.a.tools) / "winwait"), "Notepad", "60"])
            row["window_ms"] = (time.perf_counter() - start) * 1000
            if shown.returncode:
                raise RuntimeError("no window within 60 s")
            pid = int(shown.stdout.split()[1])
            row["cpu_to_window_s"] = self.cpu_seconds(pid)
            if file:
                name = file.replace("\\", "/").rsplit("/", 1)[-1]
                loaded = sh([str(Path(self.a.tools) / "winwait"), f"{name} - Notepad", "120"])
                row["file_loaded_ms"] = (time.perf_counter() - start) * 1000
                if loaded.returncode:
                    raise RuntimeError("file title never appeared")
                row["cpu_to_loaded_s"] = self.cpu_seconds(pid)
            time.sleep(idle)
            before = self.cpu_seconds(pid)
            time.sleep(3.0)
            after = self.cpu_seconds(pid)
            row["idle_cpu_percent"] = (after - before) / 3.0 * 100 if before is not None and after is not None else None
            row["rss_mb"], row["footprint_mb"] = self.memory(pid)
            if probe:
                row.update(self.probe())
                row["rss_after_probe_mb"] = None
            closing = time.perf_counter()
            if not probe:
                row.update({k: v_ for k, v_ in self.probe("close").items() if k == "close_window"})
            process.wait(timeout=60)
            row["exit_after_close_ms"] = (time.perf_counter() - closing) * 1000 if not probe else None
            row["exit_status"] = process.returncode
        except Exception as error:  # keep going; record what failed
            row["error"] = str(error)
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        usage.seek(0)
        stats = usage.read()
        usage.close()
        for key, pattern, scale in (("peak_rss_mb", r"(\d+)\s+maximum resident set size", 1 / 1048576),
                                    ("user_s", r"([\d.]+)\s+user", 1), ("sys_s", r"([\d.]+)\s+sys", 1)):
            match = re.search(pattern, stats)
            if match:
                row[key] = float(match[1]) * scale
        return row


def summarize(rows):
    """Median of each numeric field per variant."""
    out = {}
    for variant in sorted({r["variant"] for r in rows}):
        mine = [r for r in rows if r["variant"] == variant]
        fields = sorted({k for r in mine for k, v in r.items() if isinstance(v, (int, float))})
        out[variant] = {f: statistics.median([r[f] for r in mine if isinstance(r.get(f), (int, float))]) for f in fields}
        out[variant]["runs"] = len(mine)
        out[variant]["errors"] = [r["error"] for r in mine if "error" in r]
    return out


def main():
    p = argparse.ArgumentParser()
    for name in ("lifted-dir", "host-unix", "wine-root", "prefix", "tools"):
        p.add_argument(f"--{name}", required=True, type=Path)
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--large-file", type=Path, help="text file for the file-load scenario")
    p.add_argument("--json", type=Path)
    a = p.parse_args()
    bench = Bench(a)
    order = ("wine+rosetta", "lifted")
    results = {}

    def scenario(name, runs, cold=False, **kw):
        rows = []
        if not cold:
            bench.stop_server()
            # Persistent server plus one discarded launch per variant: later runs find
            # wineserver, the services and the desktop process already up.
            subprocess.Popen([bench.server, "-p"], env=bench.base_env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            for variant in order:
                bench.run(variant, idle=0.5)
        for i in range(runs):
            for variant in order:
                if cold:
                    bench.stop_server()
                row = bench.run(variant, **kw)
                rows.append(row)
                print(f"{name} #{i + 1} {variant}: " + ", ".join(
                    f"{k}={v:.1f}" for k, v in row.items() if isinstance(v, float)) +
                    (f" ERROR {row['error']}" if "error" in row else ""), flush=True)
        results[name] = {"rows": rows, "median": summarize(rows)}

    scenario("warm launch + interaction", a.runs, probe=True)
    scenario("cold launch (no wineserver running)", max(2, a.runs // 2), cold=True)
    if a.large_file:
        windows_path = "Z:" + str(a.large_file.resolve()).replace("/", "\\")
        scenario(f"open {a.large_file.stat().st_size / 1e6:.1f} MB file", max(2, a.runs // 2), file=windows_path)
    bench.stop_server()
    if a.json:
        a.json.write_text(json.dumps(results, indent=1))
    for name, data in results.items():
        print(f"\n## {name}")
        fields = sorted({f for m in data["median"].values() for f in m if f not in ("runs", "errors")})
        for f in fields:
            cells = [data["median"][v].get(f) for v in order]
            ratio = cells[1] / cells[0] if all(isinstance(c, (int, float)) for c in cells) and cells[0] else None
            print(f"{f:28} " + "  ".join(f"{c:12.2f}" if isinstance(c, (int, float)) else f"{'-':>12}" for c in cells) +
                  (f"  x{ratio:.2f}" if ratio is not None else ""))
        for v in order:
            if data["median"][v]["errors"]:
                print(f"errors {v}: {data['median'][v]['errors']}")


if __name__ == "__main__":
    main()
