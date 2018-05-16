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




class PacketForward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs): #Inicializamos las variables
        super(PacketForward, self).__init__(*args, **kwargs)

        #Configuración de MAC e IPs asociadas a los puertos: Modificar en función de la topología.
        self.port_mac_ip = {
                1: {'mac':'08:60:6e:7f:74:e7', 'ip':'192.168.0.1'},
                2: {'mac':'08:60:6e:7f:74:e8', 'ip':'192.168.1.1'}
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
        #self.logger.info("msg in")

        msg = ev.msg
        #self.logger.info("message %s", message)
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        in_port = msg.match['in_port']
        print self.arp_cache

        if (eth.ethertype == ether.ETH_TYPE_ARP):
            a = pkt.get_protocol(arp.arp)
            print a


            macip = self.port_mac_ip[in_port]
            #Si es un ping al puerto de mi router
            if a.dst_ip == macip['ip']:
                if a.opcode==1: # Request

                    self.arp_reply(a.src_ip, a.src_mac, in_port,  datapath)
                elif a.opcode==2: # Reply

                    self.arp_cache.setdefault(in_port, {})
                    self.arp_cache[in_port][a.src_ip] = a.src_mac

                    # Sacamos de cola y procesamos los forward
                    self.queue.setdefault(in_port,{})
                    self.queue[in_port].setdefault(a.src_ip, [])
                    for msg in self.queue[in_port][a.src_ip]:
                        self.set_forward_rules(msg, in_port)

                    self.queue[in_port][a.src_ip] = []


        elif (eth.ethertype == ether.ETH_TYPE_IP):
            ip = pkt.get_protocol(ipv4.ipv4)

            self.arp_cache.setdefault(in_port, {})
            self.arp_cache[in_port][ip.src]=eth.src

            self.forward(msg)


    def arp_reply(self,ip,mac, port, datapath):
        macip = self.port_mac_ip[port];
        e = ethernet.ethernet(dst=mac,
            src=macip['mac'],
            ethertype=ether.ETH_TYPE_ARP)

        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
            src_mac=macip['mac'], src_ip=macip['ip'],
            dst_mac=mac, dst_ip=ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        miprint("ARP_REPLY: Enviando paquete respuesta ARP")
        print p
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

        miprint("ARP_REQUEST: enviando paquete con peticion ARP")
        print p
        self.send_packet(datapath, port, p)



    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
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
        # Esta función debe reescribirse
        if ip=='192.168.0.2':
            return 1
        elif ip=='192.168.1.2':
            return 2

    def forward(self, msg):
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        port = self.decide_port(ip.dst)
        self.arp_cache.setdefault(port, {})
        if ip.dst in self.arp_cache[port].keys():
            self.set_forward_rules(msg, port)
        else:
            self.arp_request(ip.dst,port,datapath)
            # El paquete va a la cola hasta que vuelva la respuesta a la petición ARP.
            self.queue.setdefault(port,{})
            self.queue[port].setdefault(ip,[])
            self.queue[port][ip].append(msg)
