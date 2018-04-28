"""
Monitor for Openflow controller which sends stats to a local .csv file
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import time
import datetime
import csv

stat_filename = 'flow_stats.csv'

log = core.getLogger('StatLogger')

ipv4_attrs = of.ipv4.__dict__
nw_proto_lookup = {ipv4_attrs[k]: k for k in ipv4_attrs if isinstance(ipv4_attrs[k], int)}


def ip_to_hostname(ip):
  if isinstance(ip, tuple):
    ip = ip[0]

  if isinstance(ip, of.IPAddr):
    host_id = (ip._value & 0xff000000) >> 24
    return 'h' + str(host_id)
  else:
    raise NotImplemented('For type "{}": "{}"'.format(type(ip), ip))


class StatLogger():
  def __init__(self, filename):
    self.previous_stats = {}
    self.filename = filename

    self.raw_writer = open(self.filename, 'w')
    self.raw_writer.__enter__()
    self.writer = csv.writer(self.raw_writer, lineterminator='\n')
    self.writer.writerow([
      'time',
      'seconds',
      'type',
      'subtype',
      'src_ip',
      'dst_ip',
      'src',
      'dst',
      'connection',
      'packets/s',
      'bytes/s',
    ])

  def close(self):
    self.raw_writer.close()

  def handle_flow_stats(self, event):
    current_time = datetime.datetime.utcnow()
    current_seconds = time.mktime(current_time.timetuple()) + current_time.microsecond / 1000000.0

    # truncate for reporting
    current_time_trunc = current_time - datetime.timedelta(microseconds=current_time.microsecond)
    current_seconds_trunc = time.mktime(current_time_trunc.timetuple())

    written = 0
    for stat in event.stats:
      ether_type = of.ethernet.getNameForType(stat.match._dl_type)
      subtype = ''
      if ether_type == 'IP':
        subtype = nw_proto_lookup[stat.match.nw_proto]
        if '_' in subtype:
          subtype = subtype.split('_')[0]

      key = (
        ether_type,
        subtype,
        '{}/{}'.format(*stat.match.get_nw_src()),
        '{}/{}'.format(*stat.match.get_nw_dst()),
        ip_to_hostname(stat.match.get_nw_src()),
        ip_to_hostname(stat.match.get_nw_dst()),
        str(event.connection.ID),
      )
      values = [
        current_seconds,
        stat.packet_count,
        stat.byte_count,
        stat.duration_sec,
      ]

      previous_values = self.previous_stats.get(key, (current_seconds - 1, 0, 0, 0))
      dv = [v - pv for v, pv in zip(values, previous_values)]
      if dv[0] == 0:
        # We shouldn't get here unless there's a duplicate stat for the exact same time
        continue
      dvdt = [v / dv[0] for v in dv]

      row = [str(current_time_trunc), current_seconds_trunc] + list(key) + dvdt[1:3]
      self.writer.writerow(row)
      written += 1

      self.previous_stats[key] = values

    if written:
      self.raw_writer.flush()


def launch():
  """
  Starts the component
  """
  statlog = StatLogger(stat_filename)

  def handle_flow_stats(event):
    statlog.handle_flow_stats(event)

  core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
