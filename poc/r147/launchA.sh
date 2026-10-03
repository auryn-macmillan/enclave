#!/bin/bash
LOG=/home/dev/interfold-research/interfold/poc/r147/unitA.log
echo "[$(date -u +%FT%TZ)] UNIT_START" >> "$LOG"
/bin/bash /home/dev/interfold-research/interfold/poc/r147/A_main.sh >> "$LOG" 2>&1
echo "[$(date -u +%FT%TZ)] UNIT_END rc=$?" >> "$LOG"