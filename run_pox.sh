#!/bin/sh

# Remove misc.monitor if not logging to InfluxDB
python pox.py log.level --DEBUG misc.stats_requester misc.anomaly_controler misc.monitor misc.local_stat_logger
