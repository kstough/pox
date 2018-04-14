#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   link=TCLink,
                   autoSetMacs=True)

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s7 = net.addSwitch('s7', cls=OVSKernelSwitch)
    s8 = net.addSwitch('s8', cls=OVSKernelSwitch)
    s9 = net.addSwitch('s9', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6', defaultRoute=None)

    info( '*** Add links\n')
    net.addLink(s7, h1)
    net.addLink(s7, h2)
    net.addLink(s8, h3, bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(s8, h4, bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(h5, s9, bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(h6, s9, bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)
    net.addLink(s7, s8)
    net.addLink(s8, s9)
    net.addLink(s7, s9)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s7').start([c0])
    net.get('s8').start([c0])
    net.get('s9').start([c0])

    info( '*** Post configure switches and hosts\n')
    h5.cmdPrint('python -m SimpleHTTPServer 80 &')
    h6.cmdPrint('python -m SimpleHTTPServer 80 &')


    CLI(net)
   

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

