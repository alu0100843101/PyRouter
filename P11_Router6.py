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
						   4:('132.124.10.1','255.255.255.0')}	#Interfaz publica

		self.routingtable = [('192.168.0.0','255.255.255.0',1,None),
					   		 ('192.168.1.0','255.255.255.0',2,None),
					   		 ('192.168.2.0','255.255.255.0',3,None),
					   		 ('132.124.10.0','255.255.255.0',4,None)]	#Interfaz publica

		self.iptoMac = {'192.168.0.1':('AA:AA:AA:AA:AA:AA'),
						'192.168.1.1':('BB:BB:BB:BB:BB:BB'),
						'192.168.2.1':('CC:CC:CC:CC:CC:CC'),
						'132.124.10.1':('DD:DD:DD:DD:DD:DD')}

		self.pendigPackets = {}

		self.natbyIp = {}
		self.natbyPublicPort = {}

		self.natbyId = {}	#Tabla nat para ICMP

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

		#Si el paquete es IP
		if eth.ethertype==ether.ETH_TYPE_IP:
			ip_msg=pkt.get_protocol(ipv4.ipv4)

			transport_msg = pkt.get_protocol(udp.udp)
			if transport_msg == None:
				transport_msg = pkt.get_protocol(tcp.tcp)

			self.handle_ipv4(datapath, pkt, transport_msg, in_port, eth, ip_msg, msg)

	
			

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

	def natTraductor(self, sourceIp, destinationIp, sourcePort, destinationPort):
		print "SourceIp: %s  destinationIp: %s  sourcePort: %s  destinationPort: %s" % (sourceIp, destinationIp, sourcePort, destinationPort)
		if(destinationIp == self.interfaces[4][0]):	#Si el paquete entra desde internet
			#if destinationPort in self.natbyPublicPort.keys():
			destinationIp 		= self.natbyPublicPort[destinationPort][1]
			destinationPort 	= self.natbyPublicPort[destinationPort][0]
			print "----------------------------------------------------"
			print destinationIp
			print destinationPort
			print "----------------------------------------------------"
		else:									#Si el paquete sale a internet
			newSourceIp = self.interfaces[4][0]
			if sourceIp in self.natbyIp.keys():	#Si la ip esta en la tabla NAT
				newSourcePort = self.natbyIp[sourceIp][1]
			else:										#Si no está en la tabla

				newSourcePort = randint(1024,1124)		#1024-1124

				while newSourcePort in self.natbyPublicPort.keys():
					newSourcePort = randint(1024,1124)		#1024-1124
				self.natbyIp[sourceIp] 				= [sourcePort, newSourcePort]
				self.natbyPublicPort[newSourcePort] = [sourcePort, sourceIp]


			sourceIp 	= newSourceIp
			sourcePort 	= newSourcePort

		print "NEW SourceIp: %s  destinationIp: %s  sourcePort: %s  destinationPort: %s" % (sourceIp, destinationIp, sourcePort, destinationPort)
		return(sourceIp,destinationIp,sourcePort,destinationPort)

	def natTraductorICMP(self, sourceIp, destinationIp, icmpId):
		print "SourceIp: %s  DestinationIp: %s " % (sourceIp, destinationIp)
		if(destinationIp == self.interfaces[4][0]):	#Si el paquete entra desde internet
			#if destinationPort in self.natbyPublicPort.keys():
			destinationIp 		= self.natbyId[icmpId]
		else:									#Si el paquete sale a internet
			newSourceIp = self.interfaces[4][0]
			if sourceIp not in self.natbyId.keys():	#Si la ip no esta en la tabla NAT
				self.natbyId[icmpId]	= sourceIp

			sourceIp 	= newSourceIp

		print "NEW SourceIp: %s  destinationIp: %s" % (sourceIp, destinationIp)
		return(sourceIp,destinationIp)

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

	def handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp, src_ip, src_mac):
		if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
			return

		self.handle_nat()
		pkt = packet.Packet()
		pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src=src_mac))
		pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=src_ip,proto=pkt_ipv4.proto))
		pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,code=icmp.ICMP_ECHO_REPLY_CODE,csum=0,data=pkt_icmp.data))
		self.send_packet(datapath, port, pkt)

	

	def handle_ipv4(self, datapath, pkt, pkt_transporte, port, pkt_ethernet, pkt_ipv4, msg):
		

		if( (pkt_ipv4.dst == self.interfaces[port][0]) and  ((pkt.get_protocol(ipv4.ipv4).proto==0x06) or (pkt.get_protocol(ipv4.ipv4).proto==0x11)) and (pkt_transporte.dst_port not in self.natbyPublicPort.keys())):	#Si va destinado al router
			print 'Destinado al router' 
			if(pkt_ipv4.proto == inet.IPPROTO_ICMP):	#ICMP
				icmp_msg=pkt.get_protocol(icmp.icmp)
				self.handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, icmp_msg, self.interfaces[port][0], self.macs[port])
		else:	#Si no va con destino al router
			print 'No destinado al router'
			self.handle_nat(datapath, msg, pkt)

			

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
			

	def handle_nat(self, datapath, msg, pkt):
		ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
		
		ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
		if pkt.get_protocol(icmp.icmp) != None:	#Si pkt es ICMP
			icmp_pkt = pkt.get_protocol(icmp.icmp)
			icmpecho_pkt = icmp_pkt.data

			if(msg.match['in_port'] == 4): 
				print "Va a la red interna - ICMP" 
				sourceIp 		= ipv4_pkt.src
				destinationIp 	= ipv4_pkt.dst
				icmpId 			= icmpecho_pkt.id

				(newSourceIp, newDestinationIp) = self.natTraductorICMP(sourceIp, destinationIp, icmpId)

				(port,dstMac) = self.handle_routing(datapath,pkt,newDestinationIp)
				print "----------> port: %s  dstMac: %s newSourceIp: %s  newDestinationIp: %s" %(port,dstMac,newSourceIp,newDestinationIp)

				if(dstMac != None):
					match = datapath.ofproto_parser.OFPMatch(ipv4_src=sourceIp,ipv4_dst=destinationIp ,eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_ICMP)
					actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=self.macs[port]),
							   datapath.ofproto_parser.OFPActionSetField(eth_dst=dstMac),
							   datapath.ofproto_parser.OFPActionSetField(ipv4_dst=newDestinationIp),
							   datapath.ofproto_parser.OFPActionDecNwTtl(),
							   datapath.ofproto_parser.OFPActionOutput(port)]
					self.add_flow(datapath, 0, match, actions, msg.buffer_id)

			else:	#Sale a internet
				(port,dstMac) = self.handle_routing(datapath,pkt,ipv4_pkt.dst)
				if(dstMac != None):
					sourceIp 		= ipv4_pkt.src
					destinationIp 	= ipv4_pkt.dst
					icmpId 			= icmpecho_pkt.id

					(newSourceIp, newDestinationIp) = self.natTraductorICMP(sourceIp, destinationIp, icmpId)

					match = datapath.ofproto_parser.OFPMatch(ipv4_src=sourceIp,ipv4_dst=destinationIp ,eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_ICMP)
					actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=self.macs[port]),
							   datapath.ofproto_parser.OFPActionSetField(eth_dst=dstMac),
							   datapath.ofproto_parser.OFPActionSetField(ipv4_src=newSourceIp),
							   datapath.ofproto_parser.OFPActionDecNwTtl(),
							   datapath.ofproto_parser.OFPActionOutput(port)]
					self.add_flow(datapath, 0, match, actions, msg.buffer_id)

				
		
		if pkt.get_protocol(tcp.tcp) != None:	#Si pkt es TCP
			print "Paquete TCP"
			transport_pkt = pkt.get_protocol(tcp.tcp)

			if(msg.match['in_port'] == 4): 
				sourceIp 		= ipv4_pkt.src
				destinationIp 	= ipv4_pkt.dst
				sourcePort 		= transport_pkt.src_port
				destinationPort = transport_pkt.dst_port
				(newSourceIp, newDestinationIp, newSourcePort, newDestinationPort) = self.natTraductor(sourceIp, destinationIp, sourcePort, destinationPort)

				(port,dstMac) = self.handle_routing(datapath,pkt,newDestinationIp)
				#print "$$$$$$$$$$$$$$$$$$ port:%s dstMac:%s destinationIp:%s" %(port,dstMac,destinationIp)

				if(dstMac != None):
					match = datapath.ofproto_parser.OFPMatch(ipv4_src=sourceIp,ipv4_dst=destinationIp ,eth_type=ether.ETH_TYPE_IP, ip_proto=0x06)
					actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=self.macs[port]),
							   datapath.ofproto_parser.OFPActionSetField(eth_dst=dstMac),
							   datapath.ofproto_parser.OFPActionSetField(ipv4_dst=newDestinationIp),
							   datapath.ofproto_parser.OFPActionSetField(tcp_dst=newDestinationPort),
							   datapath.ofproto_parser.OFPActionDecNwTtl(),
							   datapath.ofproto_parser.OFPActionOutput(port)]
					self.add_flow(datapath, 0, match, actions, msg.buffer_id)

			else:	#Sale a internet
				(port,dstMac) = self.handle_routing(datapath,pkt,ipv4_pkt.dst)

				if(dstMac != None):
					sourceIp 		= ipv4_pkt.src
					destinationIp 	= ipv4_pkt.dst
					sourcePort 		= transport_pkt.src_port
					destinationPort = transport_pkt.dst_port


					(newSourceIp, newDestinationIp, newSourcePort, newDestinationPort) = self.natTraductor(sourceIp, destinationIp, sourcePort, destinationPort)

					match = datapath.ofproto_parser.OFPMatch(ipv4_src=sourceIp,ipv4_dst=destinationIp ,eth_type=ether.ETH_TYPE_IP, ip_proto=0x06)
					actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=self.macs[port]),
							   datapath.ofproto_parser.OFPActionSetField(eth_dst=dstMac),
							   datapath.ofproto_parser.OFPActionSetField(ipv4_src=newSourceIp),
							   datapath.ofproto_parser.OFPActionSetField(tcp_src=newSourcePort),
							   datapath.ofproto_parser.OFPActionDecNwTtl(),
							   datapath.ofproto_parser.OFPActionOutput(port)]
					self.add_flow(datapath, 0, match, actions, msg.buffer_id)
				


		elif pkt.get_protocol(udp.udp) != None:	#Si pkt es UDP
			transport_pkt = pkt.get_protocol(udp.udp)
			if(port == 4):	#Sale a internet
				(port,dstMac) = handle_routing(datapath,pkt,ipv4_pkt.dst)
				if(dstMac != None):
					sourceIp 		= ipv4_pkt.src
					destinationIp 	= ipv4_pkt.dst
					sourcePort 		= transport_pkt.src_port
					destinationPort = transport_pkt.dst_port
					(newSourceIp, newDestinationIp, newSourcePort, newDestinationPort) = self.natTraductor(sourceIp, destinationIp, sourcePort, destinationPort)

					match = datapath.ofproto_parser.OFPMatch(ipv4_src=sourceIp,ipv4_dst=destinationIp ,eth_type=ether.ETH_TYPE_IP, ip_proto=0x11)
					actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=self.macs[prot]),
							   datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
							   datapath.ofproto_parser.OFPActionSetField(ipv4_src=newSourceIp),
							   datapath.ofproto_parser.OFPActionSetField(udp_src=newSourcePort),
							   datapath.ofproto_parser.OFPActionDecNwTtl(),
							   datapath.ofproto_parser.OFPActionOutput(port)]
					self.add_flow(datapath, 0, match, actions, msg.buffer_id)

			elif(pkt.get_protocol(ipv4.ipv4).dst == self.interfaces[port][0]):	#Si va a la red interna
				sourceIp 		= ipv4_pkt.src
				destinationIp 	= ipv4_pkt.dst
				sourcePort 		= transport_pkt.src_port
				destinationPort = transport_pkt.dst_port
				(newSourceIp, newDestinationIp, newSourcePort, newDestinationPort) = self.natTraductor(sourceIp, destinationIp, sourcePort, destinationPort)

				(port,dstMac) = handle_routing(datapath,pkt,destinationIp)

				if(dstMac != None):
					match = datapath.ofproto_parser.OFPMatch(ipv4_src=sourceIp,ipv4_dst=destinationIp ,eth_type=ether.ETH_TYPE_IP, ip_proto=0x11)
					actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=macs[prot]),
							   datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
							   datapath.ofproto_parser.OFPActionSetField(ipv4_dst=newDestinationIp),
							   datapath.ofproto_parser.OFPActionSetField(udp_dst=newDestinationPort),
							   datapath.ofproto_parser.OFPActionDecNwTtl(),
							   datapath.ofproto_parser.OFPActionOutput(port)]
					self.add_flow(datapath, 0, match, actions, msg.buffer_id)