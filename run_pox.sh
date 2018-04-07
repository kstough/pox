#!/bin/sh

# Remove misc.monitor if not logging to InfluxDB
python pox.py log.level --DEBUG misc.anomaly_controler misc.monitor
