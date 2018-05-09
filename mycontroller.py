#!/usr/bin/python
#coding=utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.base import app_manager
from ryu.lib.mac import haddr_to_bin
from ryu.lib import mac
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from netaddr.ip import IPAddress

#from random import randint

class L3Switch ( app_manager.RyuApp ):
    # Versión de openflow 1.3
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
		super ( L3switch, self ).__init__ ( *args, **kwargs )

        # Asignación de macs a interfaces
        self.macList = {1:('11:11:11:11:11:11'),
					    2:('22:22:22:22:22:22'),
					    3:('33:33:33:33:33:33'),
					    4:('44:44:44:44:44:44')}

        # Asignación de ip's a las interfaces (Gateways)
		self.ipList = { 1:('192.168.0.1','255.255.255.0'),
						2:('192.168.1.1','255.255.255.0'),
						3:('192.168.2.1','255.255.255.0'),
						4:('192.168.3.1','255.255.255.0')}

        # Tabla de enrutamiento: Red, Mascara, Gateway
		self.routingTable = [('192.168.0.0','255.255.255.0',1),
					   		 ('192.168.1.0','255.255.255.0',2),
					   		 ('192.168.2.0','255.255.255.0',3),
					   		 ('192.168.3.0','255.255.255.0',4)]

        # Tabla de traducción de IP a MAC
		self.ipToMac = {'192.168.0.1':('11:11:11:11:11:11'),
						'192.168.1.1':('22:22:22:22:22:22'),
						'192.168.2.1':('33:33:33:33:33:33'),
						'192.168.3.1':('44:44:44:44:44:44')}
