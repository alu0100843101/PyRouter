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
from netaddr.ip import IPAddress


class L2Forwarding(app_manager.RyuApp):

	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	

	def __init__(self, *args, **kwargs):
		super(L2Forwarding, self).__init__(*args, **kwargs)
		self.macs = {1:('AA:AA:AA:AA:AA:AA'),
					 2:('BB:BB:BB:BB:BB:BB'),
					 3:('CC:CC:CC:CC:CC:CC'),
					 4:('DD:DD:DD:DD:DD:DD')}

		self.interfaces = {1:('192.168.0.1','255.255.255.0'),
						   2:('192.168.1.1','255.255.255.0'),
						   3:('192.168.2.1','255.255.255.0'),
						   4:('192.168.3.1','255.255.255.0')}

		self.routingtable = [('192.168.0.0','255.255.255.0',1,None),
					   		 ('192.168.1.0','255.255.255.0',2,None),
					   		 ('192.168.2.0','255.255.255.0',3,None),
					   		 ('192.168.3.0','255.255.255.0',4,None)]

		self.iptoMac = {}

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
			self.handle_arp(datapath, in_port, eth, arp_msg)

		#Si el paquete es IP
		if eth.ethertype==ether.ETH_TYPE_IP:
			ip_msg=pkt.get_protocol(ipv4.ipv4)
			self.handle_ipv4(datapath, pkt, in_port, eth, ip_msg, msg)

	
			

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
		print(mod)
		datapath.send_msg(mod)

	def handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
		if (pkt_arp.dst_ip == self.interfaces[port][0] and pkt_arp.opcode == arp.ARP_REQUEST):	#Si va al router el paquete ARP_REQUEST
			print 'ARP REQUEST'
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
			print 'ARP REPLY'
			self.iptoMac[pkt_arp.src_ip] = pkt_arp.src_mac
			print self.iptoMac

	def handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp, src_ip, src_mac):
		if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
			return
		pkt = packet.Packet()
		pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src=src_mac))
		pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=src_ip,proto=pkt_ipv4.proto))
		pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,code=icmp.ICMP_ECHO_REPLY_CODE,csum=0,data=pkt_icmp.data))
		self.send_packet(datapath, port, pkt)

	

	def handle_ipv4(self, datapath, pkt, port, pkt_ethernet, pkt_ipv4, msg):
		print 'Paquete ip '
		if( pkt_ipv4.dst == self.interfaces[port][0] ):	#Si va destinado al router
			print 'destinado al router'
			if(pkt_ipv4.proto == inet.IPPROTO_ICMP):	#ICMP
				icmp_msg=pkt.get_protocol(icmp.icmp)
				self.handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, icmp_msg, self.interfaces[port][0], self.macs[port])
		else:	#Si no va con destino al router
			print 'no destinado al router'
			selectNetwork = ['0.0.0.0','0.0.0.0',0,None]#Almacena ip de la red y máscara
			for network in self.routingtable:
				if IPAddress(network[0]) == (IPAddress(pkt_ipv4.dst) & IPAddress(network[1])):	#Si está en la tabla de enrutamiento
					if IPAddress(network[1]) >= IPAddress(selectNetwork[1]):	#Si la máscara de red es más grande que la seleccionada anteriormente
						selectNetwork[0] = network[0]	#Red
						selectNetwork[1] = network[1]	#Máscara
						selectNetwork[2] = network[2]	#Puerto por el que se ha de enviar
						selectNetwork[3] = network[3]	#Destino

			
			dstIPtoMAC = None				# IP a traducir
			if selectNetwork[3] == None:	# Si no hay gateway
				dstIPtoMAC = pkt_ipv4.dst
			else:							#Si hay gateway
				dstIPtoMAC = selectNetwork[3]

			if dstIPtoMAC in self.iptoMac.keys():	#Si se puede hacer la traducción de IP a MAC se añade una regla al flujo
				print 'En la tabla de traduccion'
				match = datapath.ofproto_parser.OFPMatch(ipv4_dst=pkt_ipv4.dst ,eth_type=ether.ETH_TYPE_IP) 
				actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=self.macs[selectNetwork[2]]),
						   datapath.ofproto_parser.OFPActionSetField(eth_dst=self.iptoMac[pkt_ipv4.dst]),
						   datapath.ofproto_parser.OFPActionDecNwTtl(),
						   datapath.ofproto_parser.OFPActionOutput(selectNetwork[2])]
				self.add_flow(datapath, 0, match, actions, msg.buffer_id)

			else:	# Si no se puede hacer la traducción de IP a MAC
				print 'no se puede traducir. Enviado ARP REQUEST'
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
                            dst_ip=pkt_ipv4.dst)

				arp_pkt.add_protocol(e)
				arp_pkt.add_protocol(a)

				self.send_packet(datapath, selectNetwork[2], arp_pkt)


		
