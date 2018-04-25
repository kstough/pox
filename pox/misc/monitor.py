"""
Monitor for Openflow controller which sends stats to
an InfluxDB instance for graphing using Grafana.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import datetime
import json
import influxdb
from .local_stat_logger import ip_to_hostname

log = core.getLogger('Monitor')

ipv4_attrs = of.ipv4.__dict__
nw_proto_lookup = {ipv4_attrs[k]: k for k in ipv4_attrs if isinstance(ipv4_attrs[k], int)}


def launch():
  """
  Starts the component
  """

  # def start_switch(event):
  #   log.debug("Controlling %s" % (event.connection,))
  #   Tutorial(event.connection)

  # core.openflow.addListenerByName('ConnectionUp', start_switch)

  def get_influx_client():
    config = json.load(open('influx_config.json'))
    db = config['db']
    import logging
    logging.getLogger('urllib3').setLevel(logging.INFO)
    client = influxdb.InfluxDBClient(host=config['server'], username=config['user'],
                                     password=config['pass'], database=db)
    if db not in [x['name'] for x in client.get_list_database()]:
      #   client.create_database(db)
      log.critical('database "{}" does not exist'.format(db))
      exit(1)
    return client

  influx_client = get_influx_client()

  def handle_flow_stats(event):
    current_time = datetime.datetime.utcnow()
    # always truncate to current second
    current_time = current_time - datetime.timedelta(microseconds=current_time.microsecond)
    # log.debug("Monitoring %s" % (event.connection,))
    # Monitor(event.connection)
    # log.info('{} - {}'.format(datetime.datetime.now(), event))

    keyed_matches = {}

    stat_collection = []
    for stat in event.stats:
      ether_type = of.ethernet.getNameForType(stat.match._dl_type)
      subtype = ''
      if ether_type == 'IP':
        subtype = nw_proto_lookup[stat.match.nw_proto]

      stat_point = {
        'measurement': 'flowstats',
        'tags': {
          'type': ether_type,
          'subtype': subtype,
          'src': '{}/{}'.format(*stat.match.get_nw_src()),
          'dst': '{}/{}'.format(*stat.match.get_nw_dst()),
          'src_host': ip_to_hostname(stat.match.get_nw_src()),
          'dst_host': ip_to_hostname(stat.match.get_nw_dst()),
          'connection': str(event.connection),
        },
        'time': current_time,
        'fields': {
          'packets': stat.packet_count,
          'bytes': stat.byte_count,
          'duration_sec': stat.duration_sec,
          'duration_nsec': stat.duration_nsec,
        }
      }
      key = '~'.join(':'.join(x) for x in sorted(stat_point['tags'].iteritems()))
      if key not in keyed_matches:
        keyed_matches[key] = list()
      match_list = keyed_matches[key]
      match_list.append(stat.match)

      if len(match_list) > 1:
        print('Warning: encountered duplicate key: "' + key + '"')

      # [(x.match.get_nw_src(), x.match.get_nw_dst()) for x in event.stats if x.match._dl_type == 2048 and x.match.nw_proto == 1 and '{}/{}'.format(*x.match.get_nw_src())=='10.0.0.3/32' and '{}/{}'.format(*x.match.get_nw_dst())=='10.0.0.1/32']

      # of.ethernet.getNameForType(stat.match._dl_type) # 'IP'
      # stat.match.get_nw_src() # '10.0.0.1'
      # stat.match.get_nw_dst()
      #
      # # int
      # stat.packet_count
      # len(stat.actions)
      # byte_count = {int} 882
      # cookie = {int} 0
      # duration_nsec = {int} 22000000
      # duration_sec = {int} 9
      # hard_timeout = {int} 300
      # idle_timeout = {int} 120
      # packet_count = {int} 9
      # priority = {int} 32768
      # table_id = {int} 0

      stat_collection.append(stat_point)

    if stat_collection:
      influx_client.write_points(stat_collection)

  core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
