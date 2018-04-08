"""
Based on the OpenFlow tutorial switch

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import time
import threading
import datetime
import json
import math

ipv4_attrs = pkt.IPV4.ipv4.__dict__
ipv4_protocol_to_name = {ipv4_attrs[k]: k for k in ipv4_attrs if type(ipv4_attrs[k]) is int}


class AnomalyMonitor:
  class RuleStat:
    def __init__(self):
      pass

  stats = {}

  def __init__(self, connection):
    self.log = core.getLogger('AnomalyMonitor')

    self.stat_interval_seconds = 1
    self.history_depth = 60
    self.connection = connection

    core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)
    stat_loop = threading.Thread(target=self.request_stats_loop)
    stat_loop.start()

  def request_stats_loop(self):
    next_time = math.floor(time.time()) + 0.5
    while True:
      for conn in [self.connection]:
        conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

      while (time.time() >= next_time):
        next_time += self.stat_interval_seconds
      time.sleep(next_time - time.time())

  def handle_flow_stats(self, event):
    current_time = datetime.datetime.utcnow()
    # always truncate to current second
    current_time = current_time - datetime.timedelta(microseconds=current_time.microsecond)

    from .monitor import nw_proto_lookup
    keyed_matches = {}

    stat_collection = []
    for stat in event.stats:
      ether_type = of.ethernet.getNameForType(stat.match._dl_type)
      subtype = ''
      if ether_type == 'IP':
        subtype = nw_proto_lookup[stat.match.nw_proto]

      conn_id = event.connection.ID
      src = '{}/{}'.format(*stat.match.get_nw_src())
      dst = '{}/{}'.format(*stat.match.get_nw_dst())

      key = (conn_id, src, dst)
      if key not in self.stats:
        self.stats[key] = {}

      stats = self.stats[key]


      # stat_point = {
      #   'measurement': 'flowstats',
      #   'tags': {
      #     'type': ether_type,
      #     'subtype': subtype,
      #     'src': '{}/{}'.format(*stat.match.get_nw_src()),
      #     'dst': '{}/{}'.format(*stat.match.get_nw_dst()),
      #     'connection': str(event.connection),
      #   },
      #   'time': current_time,
      #   'fields': {
      #     'packets': stat.packet_count,
      #     'bytes': stat.byte_count,
      #     'duration_sec': stat.duration_sec,
      #     'duration_nsec': stat.duration_nsec,
      #   }
      # }
      # key = '~'.join(':'.join(x) for x in sorted(stat_point['tags'].iteritems()))
      # if key not in keyed_matches:
      #   keyed_matches[key] = list()
      # match_list = keyed_matches[key]
      # match_list.append(stat.match)
      #
      # if len(match_list) > 1:
      #   print('Warning: encountered duplicate key: "' + key + '"')


class Controller(object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """

  default_timeout = of.OFP_FLOW_PERMANENT

  # default_timeout = 60 * 60  # 1h, in seconds

  def __init__(self, connection):
    self.log = core.getLogger('AnomalyController')
    self.connection = connection
    connection.addListeners(self)
    self.mac_to_port = {}
    self.anomaly_monitor = AnomalyMonitor(connection)

  def resend_packet(self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port=out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)

  def act_like_switch(self, packet, packet_in):
    logline = '{}:{}'.format(self.connection.ID, packet)

    # Learn the port for the source MAC
    port_in = self.mac_to_port.get(packet.src)
    if not port_in:
      port_in = packet_in.in_port
      self.mac_to_port[packet.src] = port_in

    # if the port associated with the destination MAC of the packet is known:
    port_out = self.mac_to_port.get(packet.dst)

    if not port_out:
      # Flood the packet out everything but the input port
      self.resend_packet(packet_in, of.OFPP_ALL)
      logline += '  {} -> {}'.format(port_in, '*')

    else:
      # Send packet out the associated port
      self.resend_packet(packet_in, port_out)
      logline += ' Flow: {} -> {}'.format(port_in, port_out)

      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      # msg.cookie = 1
      msg.idle_timeout = self.default_timeout
      msg.hard_timeout = self.default_timeout
      msg.actions.append(of.ofp_action_output(port=port_out))
      msg.actions.append(of.ofp_action_output(port=port_out))

      # Handle protocol-specific details
      if packet.type == pkt.ethernet.IP_TYPE:
        logline += '  ' + self._prepare_ipv4_rule(msg, packet)
      elif packet.type == pkt.ethernet.ARP_TYPE:
        logline += '  ' + self._prepare_arp_rule(msg, packet)
      else:
        raise NotImplemented('Unsupported packet type: "' + packet.type + '"')

      self.connection.send(msg)
    if logline:
      self.log.debug(logline)

  def _prepare_ipv4_rule(self, msg, packet):
    protocol_name = ipv4_protocol_to_name[packet.payload.protocol]
    log_extra = str(protocol_name)
    # Ignore all ports for now, makes rules simpler
    msg.match.wildcards |= \
      of.ofp_flow_wildcards_rev_map['OFPFW_TP_SRC'] | \
      of.ofp_flow_wildcards_rev_map['OFPFW_TP_DST']
    if packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL:  # IPv4/TCP
      pass
    elif packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL:  # IPv4/ICMP
      pass
    else:
      log_extra += ' Unhandled'
    return log_extra

  def _prepare_arp_rule(self, msg, packet):
    # Ignore ARP Opcode (request vs reply)
    msg.match.wildcards |= \
      of.ofp_flow_wildcards_rev_map['OFPFW_NW_PROTO']
    return ''

  def _handle_PacketIn(self, event):
    packet = event.parsed  # This is the parsed packet data.
    if not packet.parsed:
      self.log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp  # The actual ofp_packet_in message.
    self.act_like_switch(packet, packet_in)


def launch():
  log = core.getLogger()

  def start_switch(event):
    log.info("Controlling %s" % (event.connection,))
    Controller(event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_switch)
