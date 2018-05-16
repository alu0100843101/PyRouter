# -*- coding: utf-8 -*-
'''
################################################################################
##### PROYECTO FINAL DE LABORATORIO DE REDES EN INGENIERÍA DE COMPUTADORES #####
############## SDN: TOPOLOGÍA EN ÁRBOL PARA MININET USANDO PYTHON ##############
################################################################################
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
        h3 = self.addHost('h3', ip='10.0.3.10/24', mac='00:00:00:00:00:03')
        # Nota: los gateways se asignan en single3gateways.py
        self.addLink(s1, h1)
        self.addLink(s1, h2)
        self.addLink(s1, h3)

topos = { 'single3': ( lambda: MyTopo() ) }
