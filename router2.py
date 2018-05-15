# Este router está cogido de la referencia y quitado el código que no tiene que
# ver con ARP

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
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from netaddr.ip import IPAddress
from random import randint


class Packet_Forward(app_manager.RyuApp):

	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


	def __init__(self, *args, **kwargs):
		super(Packet_Forward, self).__init__(*args, **kwargs)
		self.macs = {1:('AA:AA:AA:AA:AA:AA'),
					 2:('BB:BB:BB:BB:BB:BB'),
					 3:('CC:CC:CC:CC:CC:CC'),
					 4:('DD:DD:DD:DD:DD:DD')}

		self.interfaces = {1:('10.0.1.0','255.255.255.0'),
						   2:('10.0.2.0','255.255.255.0'),
						   3:('10.0.3.0','255.255.255.0')}	#Interfaz publica

		self.routingtable = [('10.0.1.0','255.255.255.0', 1, None),
					   		 ('10.0.2.0','255.255.255.0', 2, None),
					   		 ('10.0.3.0','255.255.255.0', 3, None)]#Interfaz publica

		self.iptoMac = {'10.0.1.1':('AA:AA:AA:AA:AA:AA'),
						'10.0.2.1':('BB:BB:BB:BB:BB:BB'),
						'10.0.3.1':('CC:CC:CC:CC:CC:CC')}

		self.pendigPackets = {}

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def _switch_features_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]
		inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,actions=actions)]
		mod = parser.OFPFlowMod(datapath=datapath,priority=0, match=parser.OFPMatch(), instructions=inst)
		datapath.send_msg(mod)
###################################################

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg		       # Objeto que representa la estuctura de datos PacketIn.
		datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
		ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa
								   # de negociacion entre controlador y switch

		ofp_parser=datapath.ofproto_parser # Parser con la version OF
					   # correspondiente

		in_port = msg.match['in_port'] # Puerto de entrada.

		# Ahora analizamos el paquete utilizando las clases de la libreria packet.
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

		# Extraemos la MAC de origen
		src = eth.src

		if not(in_port in self.macs.keys()):
		    self.macs[in_port] = src

		#Extraemos la MAC de destino
		dst = eth.dst

		# Ahora creamos el match
		# fijando los valores de los campos
		# que queremos casar.
		match = ofp_parser.OFPMatch(eth_dst=dst)

		#Si el paquete es ARP
		if eth.ethertype==ether.ETH_TYPE_ARP:
			arp_msg= pkt.get_protocol(arp.arp)
			self.handle_arp(datapath, in_port, eth, arp_msg, msg)

        # Si es cualquier otro paquete se descarta


	def send_message(self,actions,ofp_parser,ofproto,msg,datapath,match):
		# Creamos el conjunto de instrucciones.
		inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		# Creamos el mensaje OpenFlow
		mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, buffer_id=msg.buffer_id,idle_timeout=20)

		# Enviamos el mensaje.
		datapath.send_msg(mod)

	def send_packet(self, datapath, port, pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt.serialize()
		data = pkt.data
		actions = [parser.OFPActionOutput(port=port)]
		out = parser.OFPPacketOut(datapath=datapath,
						  buffer_id=ofproto.OFP_NO_BUFFER,
						  in_port=ofproto.OFPP_CONTROLLER,
						  actions=actions,
						  data=data)
		datapath.send_msg(out)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		print "----------------> Añadida regla al Router <----------------------"
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
				priority=priority, match=match,
				instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
				match=match, instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
		datapath.send_msg(mod)

	def handle_arp(self, datapath, port, pkt_ethernet, pkt_arp, msg):
		print "Paquete ARP"
		if pkt_arp.src_ip not in self.iptoMac.keys():			#Si no se tiene la ip en tabla de traducciones
			print 'Ip añadida a la tabla'
			self.iptoMac[pkt_arp.src_ip] = pkt_arp.src_mac	#Se inserta

		if (pkt_arp.dst_ip == self.interfaces[port][0] and pkt_arp.opcode == arp.ARP_REQUEST):	#Si va al router el paquete ARP_REQUEST
			print "Recibido ARP REQUEST"
			e = ethernet.ethernet(dst=pkt_ethernet.src,
			      			src=self.macs[port],
			      			ethertype=ether.ETH_TYPE_ARP)
			a = arp.arp(opcode=arp.ARP_REPLY,
	    				src_mac=self.macs[port], src_ip=pkt_arp.dst_ip,
	    				dst_mac=pkt_ethernet.src, dst_ip=pkt_arp.src_ip)
			p = packet.Packet()
			p.add_protocol(e)
			p.add_protocol(a)
			self.send_packet(datapath, port, p)
		elif (pkt_arp.dst_ip == self.interfaces[port][0] and pkt_arp.opcode == arp.ARP_REPLY):	#Si va al router el paquete ARP_REPLY
			print "Recibido ARP REPLY"
			self.iptoMac[pkt_arp.src_ip] = pkt_arp.src_mac
			for (resendPkt_ethernet, resendPkt_ipv4,resendPort) in self.pendigPackets[pkt_arp.src_ip]:
				print 'Paquete Reenviado'

				e = ethernet.ethernet(dst=pkt_arp.src_mac,
					      			  src=self.macs[resendPort],
					      			  ethertype=resendPkt_ethernet.ethertype)

				p = packet.Packet()
				p.add_protocol(e)
				p.add_protocol(resendPkt_ipv4)
				self.send_packet(datapath, resendPort, p)

			self.pendigPackets[pkt_arp.src_ip] = []



	def handle_routing(self,datapath,pkt,dstIp):
		selectNetwork = ['0.0.0.0','0.0.0.0',0,None]#Almacena ip de la red y máscara
		for network in self.routingtable:
			if IPAddress(network[0]) == (IPAddress(dstIp) & IPAddress(network[1])):	#Si está en la tabla de enrutamiento
				if IPAddress(network[1]) >= IPAddress(selectNetwork[1]):	#Si la máscara de red es más grande que la seleccionada anteriormente
					selectNetwork[0] = network[0]	#Red
					selectNetwork[1] = network[1]	#Máscara
					selectNetwork[2] = network[2]	#Puerto por el que se ha de enviar
					selectNetwork[3] = network[3]	#Destino

		print "selectNetwork:%s selecNetmask:%s selectPort:%s selectGateway:%s" %(selectNetwork[0],selectNetwork[1],selectNetwork[2],selectNetwork[3])

		dstIPtoMAC = None				# IP a traducir
		if selectNetwork[3] == None:	# Si no hay gateway
			dstIPtoMAC = dstIp
		else:							#Si hay gateway
			dstIPtoMAC = selectNetwork[3]

		if dstIPtoMAC in self.iptoMac.keys():	#Si se puede hacer la traducción de IP a MAC se añade una regla al flujo
			return (selectNetwork[2], self.iptoMac[dstIPtoMAC])
		else:	# Si no se puede hacer la traducción de IP a MAC
			print "No se puede traducir IP"
			print dstIPtoMAC
			print self.iptoMac
			print "Enviado ARP REQUEST"
			print 'Red'
			print selectNetwork[0]
			print 'Puerto'
			print selectNetwork[2]
			#Se crea un mensaje ARP
			arp_pkt = packet.Packet()
			e = ethernet.ethernet(dst='FF:FF:FF:FF:FF:FF',
								  src=self.macs[selectNetwork[2]],
								  ethertype=ether.ETH_TYPE_ARP)
			a = arp.arp(opcode=arp.ARP_REQUEST,
                        src_ip=self.interfaces[selectNetwork[2]][0],
                        src_mac=self.macs[selectNetwork[2]],
                        dst_ip=dstIp)

			arp_pkt.add_protocol(e)
			arp_pkt.add_protocol(a)

			if dstIPtoMAC not in self.pendigPackets.keys():
				print 'Creada tabla de reenvio'
				self.pendigPackets[dstIp] = []

			self.pendigPackets[dstIp] = self.pendigPackets[dstIp] + [(pkt.get_protocol(ethernet.ethernet),pkt.get_protocol(ipv4.ipv4),selectNetwork[2])]

			self.send_packet(datapath, selectNetwork[2], arp_pkt)

			return (selectNetwork[2], None)
