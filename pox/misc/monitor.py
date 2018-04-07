"""
Monitor for Openflow controller which sends stats to
an InfluxDB instance for graphing using Grafana.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import time, threading, datetime, json, math
import influxdb

log = core.getLogger('Monitor')


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

    stats = event.stats
    stat_collection = []
    for stat in event.stats:
      stat_point = {
        'measurement': 'flowstats',
        'tags': {
          'type': of.ethernet.getNameForType(stat.match._dl_type),
          'src': '{}/{}'.format(*stat.match.get_nw_src()),
          'dst': '{}/{}'.format(*stat.match.get_nw_dst()),
        },
        'time': current_time,
        'fields': {
          'packets': stat.packet_count,
          'bytes': stat.byte_count,
          'duration_sec': stat.duration_sec,
          'duration_nsec': stat.duration_nsec,
        }
      }
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

  # for conn in core.openflow.connections:
  #   conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

  stat_interval_seconds = 1

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
