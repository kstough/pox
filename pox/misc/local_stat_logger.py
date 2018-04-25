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
      'type',
      'subtype',
      'src_ip',
      'dst_ip',
      'src',
      'dst',
      'connection',
      'time',
      'seconds',
      'packets',
      'bytes',
      'duration_sec',
    ])

  def close(self):
    self.raw_writer.close()

  def handle_flow_stats(self, event):
    current_time = datetime.datetime.utcnow()
    # always truncate to current second
    current_time = current_time - datetime.timedelta(microseconds=current_time.microsecond)

    written = 0
    for stat in event.stats:
      ether_type = of.ethernet.getNameForType(stat.match._dl_type)
      subtype = ''
      if ether_type == 'IP':
        subtype = nw_proto_lookup[stat.match.nw_proto]
        if '_' in subtype:
          subtype = subtype.split('_')[0]

      row = [
        ether_type,
        subtype,
        '{}/{}'.format(*stat.match.get_nw_src()),
        '{}/{}'.format(*stat.match.get_nw_dst()),
        ip_to_hostname(stat.match.get_nw_src()),
        ip_to_hostname(stat.match.get_nw_dst()),
        str(event.connection.ID),
        current_time,
        time.mktime(current_time.timetuple()),
        stat.packet_count,
        stat.byte_count,
        stat.duration_sec,
      ]
      self.writer.writerow(row)
      written += 1

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
