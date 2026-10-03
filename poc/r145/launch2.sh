#!/bin/bash
LOG=/home/dev/interfold-research/poc/r145/unitA2.log
echo "[$(date -u +%FT%TZ)] UNIT_START" >> "$LOG"
/bin/bash /home/dev/interfold-research/poc/r145/A2.sh >> "$LOG" 2>&1
echo "[$(date -u +%FT%TZ)] UNIT_END rc=$?" >> "$LOG"