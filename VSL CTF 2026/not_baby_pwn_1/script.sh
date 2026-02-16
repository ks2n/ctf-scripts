#!/usr/bin/env bash
set -u

OUT="text.txt"
N=200          # số lần chạy
TIMEOUT=2      # timeout mỗi lần (giây)

echo "==== START: $(date) ====" >> "$OUT"

for i in $(seq 1 "$N"); do
  echo "===== RUN $i ===== $(date) =====" >> "$OUT"

  python solve.py
done

echo "==== END: $(date) ====" >> "$OUT"
