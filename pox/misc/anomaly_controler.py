"""
Based on the OpenFlow tutorial switch

"""
import collections

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import time
import threading
import datetime
import json
import math
import numpy as np

ipv4_attrs = pkt.IPV4.ipv4.__dict__
ipv4_protocol_to_name = {ipv4_attrs[k]: k for k in ipv4_attrs if type(ipv4_attrs[k]) is int}


# Note: all flow stats are in packets and bytes (not bits)
class AnomalyMonitor:

  def __init__(self, connection, mapped_ports):
    self.limit_pps = 30 * 1000  # 30 kpps
    self.limit_bits_s = 20 * 1024 * 1024  # 20 Mbps
    self.limit_bps = self.limit_bits_s / 8

    self.default_timeout = 120  # Initially block aggressive clients for 10s
    self.timeout_exp_factor = 2  # Multiply timeout by this much each time
    self.max_timeout = 65535

    self.log = core.getLogger('AnomalyMonitor')
    self.stats = {}
    self.rules = {}
    self.timeouts = {}

    self.stat_interval_seconds = 1
    self.history_depth = 10
    self.connection = connection
    self.mapped_ports = mapped_ports

    core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)

  def handle_flow_stats(self, event):
    if event.connection != self.connection:
      return

    current_time = datetime.datetime.utcnow()
    current_seconds = time.mktime(current_time.timetuple())

    # always truncate to current second, makes stats keeping easier
    current_time = current_time - datetime.timedelta(microseconds=current_time.microsecond)

    # Step 1: aggregate event data
    stat_collection = {}
    for stat in event.stats:
      conn_id = event.connection.ID
      src = '{}/{}'.format(*stat.match.get_nw_src())
      dst = '{}/{}'.format(*stat.match.get_nw_dst())
      first, second = sorted((src, dst))
      key = (conn_id, first, second)

      packets = stat.packet_count
      bytes_ = stat.byte_count

      if key in stat_collection:
        stats = (current_seconds,
                 stat_collection[key][1] + packets,
                 stat_collection[key][2] + bytes_)
      else:
        stats = (current_seconds, packets, bytes_)
      stat_collection[key] = stats

      if key not in self.rules:
        self.rules[key] = []
      if stat.match not in self.rules[key]:
        self.rules[key].append(stat.match)

      if key not in self.timeouts:
        self.timeouts[key] = self.default_timeout

    # Step 2: update our internal stat counters
    num_stats_updated = 0
    for key in stat_collection:
      stats = stat_collection[key]
      if key not in self.stats:
        # Populate (current index, data)
        self.reset_stats_for_key(key)
        # self.stats[key] = (0, np.zeros((self.history_depth, 5), dtype=np.float))

      index, conn_stats = self.stats[key]
      prev_index = (index + self.history_depth - 1) % self.history_depth

      if conn_stats[prev_index][0] == current_seconds:
        continue

      conn_stats[index][0:3] = stats
      if conn_stats[prev_index][0] > 0:
        diff = conn_stats[index] - conn_stats[prev_index]
        if diff[0] <= 0:
          self.log.warning('Div by zero in stat diff')
        pps = diff[1] / diff[0]
        bps = diff[2] / diff[0]
        conn_stats[index][3:5] = (pps, bps)

      index = (index + 1) % self.history_depth
      self.stats[key] = (index, conn_stats)
      num_stats_updated += 1

    if num_stats_updated == 0:
      return

    # Step 3: Check for high-bandwidth connections
    for key in self.stats:
      index, data = self.stats[key]
      _, _, _, pps_avg, bps_avg = np.average(data, axis=0)
      _, _, _, pps_max, bps_max = np.average(data, axis=0)
      # self.log.debug('{}: {:-10.3f} kpps, {:-10.3f} Mbps'.format(key, pps_avg / 1000,
      #                                                            bps_avg * 8 / 1024 / 1024))

      if pps_avg > self.limit_pps or bps_avg > self.limit_bps:
        self.log.debug('{}: {:-10.3f} kpps, {:-10.3f} Mbps'.format(key, pps_avg / 1000,
                                                                   bps_avg * 8 / 1024 / 1024))
        if pps_avg > self.limit_pps:
          self.log.info('Client exceeded packets per second')
        else:
          self.log.info('Client exceeded bytes per second')

        # Finally, throttle the connection
        self.act_on_busy_link(key)
        self.reset_stats_for_key(key)

  def act_on_busy_link(self, key):
    timeout = self.timeouts[key]
    self.timeouts[key] = min(timeout * self.timeout_exp_factor, self.max_timeout)

    self.log.info('{}: Blocking link: {} for {} s'.format(datetime.datetime.now(), key, timeout))

    # Take all rules for this client and block them all
    for match in self.rules[key]:
      msg = of.ofp_flow_mod()
      msg.match = match
      msg.idle_timeout = timeout
      msg.hard_timeout = timeout
      msg.out_port = of.OFPP_NONE
      self.connection.send(msg)

    self.rules[key] = []

  def reset_stats_for_key(self, key):
    self.stats[key] = (0, np.zeros((self.history_depth, 5), dtype=np.float))


class Controller(object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """

  default_timeout = of.OFP_FLOW_PERMANENT

  # default_timeout = 60 * 60  # 1h, in seconds

  def __init__(self, connection):
    self.log = core.getLogger('AnomalyController')
    self.log.info('Controller.init: {:x}'.format(id(self)))
    self.connection = connection
    connection.addListeners(self)
    self.mac_to_port = {}
    self.anomaly_monitor = AnomalyMonitor(connection, self.mac_to_port)
    self.recent_matches = {}

    def clear_recent_matches():
      while True:
        for key in list(self.recent_matches.keys()):
          if datetime.datetime.utcnow() - self.recent_matches[key] > datetime.timedelta(seconds=10):
            timestamp = self.recent_matches.pop(key)
            # self.log.debug('Removed recent rule: {}  {}'.format( timestamp , key))
        time.sleep(2)

    stat_loop = threading.Thread(target=clear_recent_matches)
    stat_loop.start()

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
    if packet.type == pkt.ethernet.IPV6_TYPE:
      return
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
      # logline += '  {} -> {}'.format(port_in, '*')
      logline = None

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

      # Handle protocol-specific details
      if packet.type == pkt.ethernet.IP_TYPE:
        logline += '  ' + self._prepare_ipv4_rule(msg, packet)
      elif packet.type == pkt.ethernet.ARP_TYPE:
        logline += '  ' + self._prepare_arp_rule(msg, packet)
      else:
        raise NotImplemented('Unsupported packet type: "' + packet.type + '"')

      # Check to see if we've recently sent a rule for this flow
      # flow_match = of.ofp_match.from_packet(packet)
      # flow_match.wildcards
      if msg.match in self.recent_matches:
        return  # assume we've already created this rule
      self.recent_matches[msg.match] = datetime.datetime.utcnow()

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
