"""
Simple timed stat requester. Requests stats that all other methods can listen for
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
import time
import threading
import math

log = core.getLogger()

stat_interval_seconds = 1


def launch():
  def request_stats_loop():
    next_time = math.floor(time.time()) + 0.5
    while True:
      for conn in core.openflow.connections:
        conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

      while (time.time() >= next_time):
        next_time += stat_interval_seconds
      time.sleep(next_time - time.time())

  stat_loop = threading.Thread(target=request_stats_loop)
  stat_loop.start()
