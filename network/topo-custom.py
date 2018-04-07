"""Custom topology example

    s7 ---- s8 ---- s9
   /  \    /  \    /  \
  h1  h2  h3  h4  h5  h6

"""

from mininet.topo import Topo

print('Loading MyTopo')

class MyTopo(Topo):
  "Simple topology example."

  def __init__(self):
    Topo.__init__(self)

    # Add hosts and switches
    h1, h2, h3, h4, h5, h6 = (self.addHost('h' + str(i + 1)) for i in range(6))
    s7, s8, s9 = (self.addSwitch('s' + str(i + 7)) for i in range(3))

    # Add links
    self.addLink(h1, s7)
    self.addLink(h2, s7)
    self.addLink(s7, s8)
    self.addLink(h3, s8)
    self.addLink(h4, s8)
    self.addLink(s8, s9)
    self.addLink(h5, s9)
    self.addLink(h6, s9)


topos = {'mytopo': (lambda: MyTopo())}
