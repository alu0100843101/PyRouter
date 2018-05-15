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

        #Configuración de MAC e IPs asociadas a los puertos: Modificar en función de la topología.


        self.port_mac_ip = {
                1: {'mac':'26:7f:af:b9:38:af', 'ip':'10.0.1.1'}, # En
                2: {'mac':'d2:36:c9:69:7e:b8', 'ip':'10.0.2.1'},
                3: {'mac':'0e:24:19:e2:ba:bf', 'ip':'10.0.3.1'},
        }

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
        miprint("He aquí un paquete")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        in_port = msg.match['in_port']
        miprint("Mi ARP Cache es: ")
        print self.arp_cache

        if (eth.ethertype == ether.ETH_TYPE_ARP):
            a = pkt.get_protocol(arp.arp)
            print a
            miprint("Peticion ARP")
            macip = self.port_mac_ip[in_port]
            miprint("Comparando " + a.dst_ip + " con " + macip['ip'])
            # Si está pidiendo la ip del puerto de mi Router
            if a.dst_ip == macip['ip']:
                miprint("Paquete ARP al puerto de mi router")
                if a.opcode==1: # Request
                    miprint("El paquete es una peticion")
                    self.arp_reply(a.src_ip, a.src_mac, in_port,  datapath)
                elif a.opcode==2: # Reply
                    miprint("El paquete es una respuesta")
                    self.arp_cache.setdefault(in_port, {})
                    self.arp_cache[in_port][a.src_ip] = a.src_mac

                    # Sacamos de cola y procesamos los forward
                    self.queue.setdefault(in_port,{})
                    self.queue[in_port].setdefault(a.src_ip, [])
                    for msg in self.queue[in_port][a.src_ip]:
                        self.set_forward_rules(msg, in_port)
                    self.queue[in_port][a.src_ip] = []
            # Si está pidiendo otra ip tengo que ver
            else:
                self.forward(msg)



        elif (eth.ethertype == ether.ETH_TYPE_IP):
            ip = pkt.get_protocol(ipv4.ipv4)

            self.arp_cache.setdefault(in_port, {})
            self.arp_cache[in_port][ip.src]=eth.src

            self.forward(msg)


    def arp_reply(self,ip,mac, port, datapath):
        miprint("Generando respuesta para el puerto " + str(port))
        macip = self.port_mac_ip[port];
        miprint("En ese puerto tengo esta informacion")
        print macip
        e = ethernet.ethernet(dst=mac,
            src=macip['mac'],
            ethertype=ether.ETH_TYPE_ARP)

        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
            src_mac=macip['mac'], src_ip=macip['ip'],
            dst_mac=mac, dst_ip=ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        miprint("He aquí la respuesta ARP")
        print p
        # Guardar entrada en la tabla del switch
        # TODO: para que no vuelva a preguntar, añadir
        # una entrada en la tabla de flujo
        self.send_packet(datapath, port, p)

    def arp_request(self,ip, port,  datapath):
        macip = self.port_mac_ip[port];
        e = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
            src=macip['mac'],
            ethertype=ether.ETH_TYPE_ARP)

        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=1,
            src_mac=macip['mac'], src_ip=macip['ip'],
            dst_mac='00:00:00:00:00:00', dst_ip=ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        print p
        self.send_packet(datapath, port, p)



    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        miprint("Mandando paquete en send_packet")
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
        miprint("A qué puerto mando este paquete?")
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
        miprint("Este paquete no es para mí -> forward!!!")
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        ethertype = pkt.get_protocol(ethernet.ethernet).ethertype
        if (ethertype == ether.ETH_TYPE_ARP):
            header = pkt.get_protocol(arp.arp)
            pkt_dst = header.dst_ip
            miprint("Es un paquete arp")
        elif (ethertype == ether.ETH_TYPE_IP):
            header = pkt.get_protocol(ipv4.ipv4)
            pkt_dst = header.dst
            miprint("Es un paquete ipv4")
        miprint("Esto es la cabecera del paquete")
        print header
        port = self.decide_port(pkt_dst)
        self.arp_cache.setdefault(port, {})
        miprint("Sale por el puerto " +  str(port))
        if pkt_dst in self.arp_cache[port].keys():
            if (ethertype is ether.ETH_TYPE_IP):
                self.set_forward_rules(msg, port)
        else:
            self.arp_request(pkt_dst,port,datapath)
            # El paquete va a la cola hasta que vuelva la respuesta a la petición ARP.
            self.queue.setdefault(port,{})
            self.queue[port].setdefault(header,[])
            self.queue[port][header].append(msg)
