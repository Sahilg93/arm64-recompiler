#!/usr/bin/env python3
"""Benchmark suite: Wine+Rosetta vs recompiled ARM64 vs upstream native, across corpus .exe files.

Run from the repository root:
    python3 work/bench_suite.py [--runs N] [--warmup W] [--only CASE ...]

Each case runs every variant N+W times, discards W warmups, checks exit status
and that stdout matches the upstream-native output byte-for-byte, and reports
min / median / p95 wall time and peak RSS.
"""
import argparse, json, math, os, random, re, statistics, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
W = ROOT / 'work'
DATA = W / 'bench-suite-data'
ENV = dict(os.environ, WINEDEBUG='-all', MVK_CONFIG_LOG_LEVEL='0')
WINE = [sys.executable, str(ROOT / 'outputs/arm64-recompiler/run_windows.py'),
        '--wine', str(W / 'wine/Wine Stable.app/Contents/Resources/wine/bin/wine'),
        '--prefix', str(W / 'wine/prefix')]
NATIVE = W / 'native-tools/extract/native-tools'


def make_data():
    DATA.mkdir(exist_ok=True)
    small = DATA / 'small.json'
    if not small.exists():
        small.write_text(json.dumps({'a': [3, 1, 2], 'name': 'bench'}))
    big = DATA / 'records.json'
    if not big.exists():
        rng = random.Random(1234)
        recs = [{'id': i, 'user': f'user{rng.randrange(500)}',
                 'score': rng.randrange(100000) / 100,
                 'tags': rng.sample(['a', 'b', 'c', 'd', 'e', 'f'], 3),
                 'msg': ''.join(rng.choice('abcdefghij ') for _ in range(40))}
                for i in range(50000)]
        big.write_text(json.dumps(recs))
    return small, big


def cases():
    small, big = make_data()
    heavy = ('group_by(.user) | map({user: .[0].user, n: length, '
             'total: (map(.score) | add), tags: (map(.tags[]) | unique)}) '
             '| sort_by(-.total) | .[:20]')
    regex = '[.[] | select(.msg | test("a.b.c")) | .id] | length'
    jq_variants = lambda args: {
        'wine': [*WINE, str(W / 'corpus/jq.exe'), *args],
        'recompiled': [str(W / 'jq-verify/jq'), *args],
        'native': [str(NATIVE / 'jq'), *args],
    }
    return {
        'plink -V': {
            'wine': [*WINE, str(W / 'corpus/plink.exe'), '-V'],
            'recompiled': [str(W / 'plink-o2-fast'), '-V'],
            'native': [str(NATIVE / 'plink'), '-V'],
        },
        'jq --version': jq_variants(['--version']),
        'jq sort (tiny)': jq_variants(['-c', '.a|sort', str(small)]),
        'jq group_by (50k recs, 6 MB)': jq_variants(['-c', heavy, str(big)]),
        'jq regex (50k recs)': jq_variants([regex, str(big)]),
    }


def bench(cmd, runs, warmup, timeout):
    rows, out = [], None
    for i in range(runs + warmup):
        t = time.perf_counter()
        p = subprocess.run(['/usr/bin/time', '-l', *cmd], capture_output=True, env=ENV, timeout=timeout)
        ms = (time.perf_counter() - t) * 1000
        if p.returncode != 0:
            raise RuntimeError(f'exit {p.returncode}: {p.stderr[-400:].decode(errors="replace")}')
        rss = int(re.search(rb'(\d+)\s+maximum resident set size', p.stderr)[1]) / 1e6
        if out is None:
            out = p.stdout
        elif p.stdout != out:
            raise RuntimeError('stdout differs between runs')
        if i >= warmup:
            rows.append((ms, rss))
    ts = sorted(r[0] for r in rows)
    return {'min': ts[0], 'median': statistics.median(ts), 'p95': ts[math.ceil(.95 * len(ts)) - 1],
            'rss': max(r[1] for r in rows), 'stdout': out}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', type=int, default=20)
    ap.add_argument('--wine-runs', type=int, default=10, help='Wine is slow; fewer runs by default')
    ap.add_argument('--warmup', type=int, default=2)
    ap.add_argument('--only', nargs='*')
    ap.add_argument('--json', type=Path, default=W / 'bench-suite-results.json')
    a = ap.parse_args()
    results = {}
    for name, variants in cases().items():
        if a.only and not any(o in name for o in a.only):
            continue
        print(f'\n## {name}', flush=True)
        res = {}
        for v in ('native', 'recompiled', 'wine'):
            try:
                res[v] = bench(variants[v], a.wine_runs if v == 'wine' else a.runs, a.warmup, 300)
            except Exception as e:
                res[v] = {'error': str(e)[:300]}
                print(f'  {v:<11} ERROR {e}', flush=True)
                continue
            r = res[v]
            print(f'  {v:<11} {r["min"]:9.2f} {r["median"]:9.2f} {r["p95"]:9.2f} ms  rss {r["rss"]:7.2f} MB', flush=True)
        ref = res.get('native', {}).get('stdout')
        for v, r in res.items():
            if 'stdout' in r:
                # Windows builds emit CRLF; compare modulo line endings.
                r['matches_native'] = ref is not None and r.pop('stdout').replace(b'\r\n', b'\n') == ref
        results[name] = res
    a.json.write_text(json.dumps(results, indent=1))

    print('\n| Case | Variant | Min / Median / P95 (ms) | vs Wine (median) | Peak RSS | Output = native |')
    print('| --- | --- | ---: | ---: | ---: | :---: |')
    for name, res in results.items():
        wmed = res.get('wine', {}).get('median')
        for v in ('recompiled', 'wine', 'native'):
            r = res.get(v, {})
            if 'error' in r:
                print(f'| {name} | {v} | error | | | |'); continue
            sp = f'{wmed / r["median"]:.2f}×' if wmed else '—'
            print(f'| {name} | {v} | {r["min"]:.2f} / {r["median"]:.2f} / {r["p95"]:.2f} | {sp} | '
                  f'{r["rss"]:.2f} MB | {"✓" if r["matches_native"] else "✗"} |')
    print(f'\nraw results: {a.json}')


if __name__ == '__main__':
    main()
