# -*- coding: utf-8 -*-


'''
Topología linear con 2 switches
            [s1]-----[s2]
             |         |
            [h1]      [h2]
'''
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info

class MyTopo ( Topo ):

    def __init__ ( self ):

        # Nivel de inicio
        sw_level = 0

        # Llama al constructor de la clase de la que hereda
        # super(myTopo, self).__init__()
        Topo.__init__ ( self )

        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='10.0.1.10/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.2.10/24', mac='00:00:00:00:00:02')
        # Nota: los gateways se asignan en single3gateways.py
        self.addLink(s1, h1)
        self.addLink(s1, h2)
        self.addLink(s1, s2)

topos = { 'single3': ( lambda: MyTopo() ) }
