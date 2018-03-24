# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()

# default_timeout = of.OFP_FLOW_PERMANENT
default_timeout = 60 * 60  # 1h, in seconds

ipv4_attrs = pkt.IPV4.ipv4.__dict__
ipv4_protocol_to_name = {ipv4_attrs[k]: k for k in ipv4_attrs if type(ipv4_attrs[k]) is int}


class Tutorial(object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """

  def __init__(self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

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

  # import pox.lib.packet
  # packet: pox.lib.packet, packet_in: ofp_packet_in
  def act_like_hub(self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    log.info(str(packet))

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)
    # self.resend_packet(packet_in, 2)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).

  def act_like_switch(self, packet, packet_in):
    """
    Implement switch-like behavior.
    """
    logline = str(packet)

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
      log_extra = '{} -> {}'.format(port_in, port_out)

      # Add flow entry for future packets
      log_extra = '[Flow: {}]'.format(log_extra)

      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      # msg.cookie = 1
      msg.idle_timeout = 120
      msg.hard_timeout = 300
      msg.actions.append(of.ofp_action_output(port=port_out))

      if packet.type == pkt.ethernet.IP_TYPE:  # IPv4
        protocol_name = ipv4_protocol_to_name[packet.payload.protocol]
        log_extra += '  ' + str(protocol_name)
        if packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL:  # IPv4/TCP
          # Ignore TCP ports (otherwise we get a lot of rules due to different client ports)
          msg.match.wildcards |= \
            of.ofp_flow_wildcards_rev_map['OFPFW_TP_SRC'] | \
            of.ofp_flow_wildcards_rev_map['OFPFW_TP_DST']

        elif packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL:  # IPv4/ICMP
          pass # Nothing special for ICMP
        else:
          log_extra += ' Unhandled'

        self.connection.send(msg)
        logline += '  ' + log_extra

      elif packet.type == pkt.ethernet.ARP_TYPE:

        self.connection.send(msg)
        logline += '  ' + log_extra
        pass

    # else:  # Not IP_TYPE
    #   self.resend_packet(packet_in, of.OFPP_ALL)
    #   # logline = None

    if logline:
      log.debug(logline)

  def _handle_PacketIn(self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed  # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp  # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    # self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)


def launch():
  """
  Starts the component
  """

  def start_switch(event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_switch)
