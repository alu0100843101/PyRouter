#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.ofproto import ether
from ipaddress import IPv4Address, IPv4Network, IPv4Interface

def miprint(s):
    print "*"*10+s


class PacketForward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs): #Inicializamos las variables
        super(PacketForward, self).__init__(*args, **kwargs)

        # Las mac's de la interfaces del switch s1 está en un fichero.
        # maclist es variable local porque no se usa en otro sitio.
        maclist = []
        f = open('macaddr2.tmp', 'r')
        # el -1 es para quitar el \n
        maclist.append(f.readline()[:-1])
        maclist.append(f.readline()[:-1])
        maclist.append(f.readline()[:-1])
        f.close()

        self.port_mac_ip = {
                1: {'mac': maclist[0], 'ip':'10.0.1.1'}, # En
                2: {'mac': maclist[1], 'ip':'10.0.2.1'},
                3: {'mac': maclist[2], 'ip':'10.0.3.1'},
        }

        miprint("__INIT__: port_mac_ip")
        print self.port_mac_ip

        self.port_to_network = {
            1: {'netip':'10.0.1.0', 'netmask':'255.255.255.0'},
            2: {'netip':'10.0.2.0', 'netmask':'255.255.255.0'},
            3: {'netip':'10.0.3.0', 'netmask':'255.255.255.0'},
        }

        self.arp_cache = {}
        self.queue={}

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
        actions)]
        if buffer_id:
             mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
             mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        miprint("ADD_FLOW: Añadiendo regla")
        print mod
        datapath.send_msg(mod)



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def event_switch_enter_handler(self, ev):
        msg =ev.msg

        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        self.logger.info("switch connected %s", dp)


        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        self.add_flow(datapath=dp, priority=0, match=match, actions=actions)




    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        miprint("PACKET_IN: He aquí un paquete")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        in_port = msg.match['in_port']
        miprint("PACKET_IN: Mi ARP Cache es: ")
        print self.arp_cache

        if (eth.ethertype == ether.ETH_TYPE_ARP):
            a = pkt.get_protocol(arp.arp)
            print a
            miprint("PACKET_IN: Peticion ARP")
            macip = self.port_mac_ip[in_port]
            miprint("PACKET_IN: Comparando " + a.dst_ip + " con " + macip['ip'])
            # Si es para la interfaz de mi router
            if a.dst_ip == macip['ip']:
                miprint("PACKET_IN: Paquete ARP al puerto de mi router")
                if a.opcode==1: # Si es una petición, devolver mi mac en ese puerto
                    miprint("PACKET_IN: El paquete es una peticion")
                    # Le digo al host que la mac que está buscando es la de mi interfaz
                    self.arp_reply(a.src_ip, a.src_mac, in_port,  datapath)
                elif a.opcode==2: # Si es una respuesta, asociar mac e ip origen a ese puerto
                    miprint("PACKET_IN: El paquete es una respuesta")
                    self.arp_cache.setdefault(in_port, {})
                    self.arp_cache[in_port][a.src_ip] = a.src_mac
                    # Sacamos de cola y procesamos los forward
                    self.queue.setdefault(in_port,{})
                    self.queue[in_port].setdefault(a.src_ip, [])
                    for msg in self.queue[in_port][a.src_ip]:
                        self.set_forward_rules(msg, in_port)
                    self.queue[in_port][a.src_ip] = []
            # Si está pidiendo la ip de otro sitio,
            # decirle que la mac que está buscando es la de mi interfaz
            # y guardar la mac del host destino que estoy buscando para
            # posteriormente reenviar el paquete a ese host
            else:
                # En teoría el opcode siempre es 1 si es para otra red,
                # porque la respuesta ARP no se puede hacer de una red
                # a otra.
                # NO????????????????????????????????????????????????
                if a.opcode==1:
                    # Responder con la mac del puerto
                    self.arp_reply(a.src_ip, a.src_mac, in_port,  datapath)
                    # Buscar mac del host y guardarla
                    # Primero buscar el puerto en el que está esa ip
                    out_port = decide_port(a.src_ip)
                    # Luego enviar un broadcast a ese puerto preguntando
                    # por ese host
                    self.arp_request(a.dst_ip, out_port, datapath)
                    # Lo siguiente es recibir la respuesta con otro nuevo
                    # packetIn, por lo que no hace falta nada mas aquí
                    # porque vuelve arriba




        elif (eth.ethertype == ether.ETH_TYPE_IP):
            ip = pkt.get_protocol(ipv4.ipv4)

            self.arp_cache.setdefault(in_port, {})
            self.arp_cache[in_port][ip.src]=eth.src

            self.forward(msg)

    # Metodo para enviar respuestas ARP desde el switch
    def arp_reply(self,ip,mac, port, datapath):
        # ip: IP desde la que se está preguntando (ip del host)
        # mac: mac desde la que se está perguntando (mac del host)
        # port: puerto en el que se está preguntando
        miprint("ARP_REPLY: Generando respuesta para el puerto " + str(port))
        # Obtener MAC e Ip del puerto del switch
        macip = self.port_mac_ip[port];
        miprint("ARP_REPLY: Información del puerto " + str(port))
        print macip

        # Crear cabecera ethernet con mac destino, la del host,
        # mac origen, la de mi interfaz,
        # tipo de paquete, ARP.
        e = ethernet.ethernet(dst=mac,
            src=macip['mac'],
            ethertype=ether.ETH_TYPE_ARP)
        # Crear cabecera ARP con
        # campos para indicar que es ethernet,ip,maclen,iplen,reply
        # mac origen, la de mi interfaz
        # ip origen, la de mi interfaz
        # mac destino, la del host
        # ip destino, la del host
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
            src_mac=macip['mac'], src_ip=macip['ip'],
            dst_mac=mac, dst_ip=ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        miprint("ARP_REPLY: Enviando respuesta ARP al puerto " + str(port))
        print p
        self.send_packet(datapath, port, p)

    # Metodo para enviar peticiones ARP desde el switch
    def arp_request(self,ip, port,  datapath):
        # ip: ip del host al que se quiere preguntar
        # port: puerto en donde está ese host
        # obtener la ip y mac de ese puerto del switch
        macip = self.port_mac_ip[port];
        # construir cabecera Ethernet con
        # mac origen, la mac del puerto
        # mac destino, todo a ff porque es un broadcast
        # tipo ARP
        e = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
            src=macip['mac'],
            ethertype=ether.ETH_TYPE_ARP)
        # Construir cabecera ARP con
        # numeritos que indican ip,mac,ethernet etc. (siempre iguales)
        # opcode 1 porque es request
        # mac origen, la mac del puerto
        # ip origen, la ip de mi puerto,
        # mac destino todo a 00 porque es desconocida
        # ip destino, la ip del host
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=1,
            src_mac=macip['mac'], src_ip=macip['ip'],
            dst_mac='00:00:00:00:00:00', dst_ip=ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        miprint("ARP_REQUEST: Enviando PETICION ARP al puerto " + str(port))
        print p
        self.send_packet(datapath, port, p)



    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        miprint("SEND_PACKET: Enviando paquete")
        self.logger.info("%s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def set_forward_rules(self,msg,port):
        # Esta función debe reescribirse
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt=packet.Packet(msg.data)
        miprint("SET_FORWARD_RULES: Añadiendo reglas para paquete:")
        print pkt
        eth=pkt.get_protocol(ethernet.ethernet)
        ip=pkt.get_protocol(ipv4.ipv4)

        new_src_mac=self.port_mac_ip[port]['mac']
        new_dst_mac=self.arp_cache[port][ip.dst]


        match = parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP )
        actions=[
            parser.OFPActionSetField(eth_dst=new_dst_mac),
            parser.OFPActionSetField(eth_src=new_src_mac),
            parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(port)
        ]

        self.add_flow(datapath=datapath, priority=1, match=match, actions=actions, buffer_id=msg.buffer_id,
                      idle_timeout=20)

    def decide_port(self, ip):
        miprint("DECIDE_PORT: A qué puerto mando este paquete?")
        # Libreria ipaddress
        ipaddr1 = IPv4Address(unicode(str(ip)))

        # Importante ordenar los if de mayor tamaño de máscara
        # a menor para que siempre coja la red con mayor máscara
        if ipaddr1 in IPv4Network(unicode('10.0.1.0/24')):
            return 1
        elif ipaddr1 in IPv4Network(unicode('10.0.2.0/24')):
            return 2
        elif ipaddr1 in IPv4Network(unicode('10.0.3.0/24')):
            return 3


    def forward(self, msg):
        miprint("FORWARD: este paquete no es para mi")
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        port = self.decide_port(ip.dst)
        self.arp_cache.setdefault(port, {})
        miprint("FORWARD: Mi arp cache es")
        print self.arp_cache
        if ip.dst in self.arp_cache[port].keys():
            self.set_forward_rules(msg, port)
        else:
            self.arp_request(ip.dst,port,datapath)
            # El paquete va a la cola hasta que vuelva la respuesta a la petición ARP.
            self.queue.setdefault(port,{})
            self.queue[port].setdefault(ip,[])
            self.queue[port][ip].append(msg)
