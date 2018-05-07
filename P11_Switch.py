#!/usr/bin/python
#coding=utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.base import app_manager
from ryu.lib.mac import haddr_to_bin
from ryu.lib import mac

class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    tabla = {}
    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)

        #######################################
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
        msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
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

        if not(src in self.tabla.keys()):
            self.tabla[src] = in_port

        dst = eth.dst


        # Ahora creamos el match  
        # fijando los valores de los campos 
        # que queremos casar.
        match = ofp_parser.OFPMatch(eth_dst=dst)

        if haddr_to_bin(dst) == (mac.BROADCAST or (mac.is_multicast(haddr_to_bin(dst)))):
            actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.send_message(actions,ofp_parser,ofproto,msg,datapath,match)
            print 'hola1'
        elif dst in self.tabla.keys(): 
            if in_port == self.tabla[dst]:
                print 'hola2'
                actions = []
                self.send_message(actions, ofp_parser,ofproto,msg,datapath,match)
            else:
                print 'hola3'
                actions = [ofp_parser.OFPActionOutput(self.tabla[dst])]
                self.send_message(actions,ofp_parser,ofproto,msg,datapath,match)
        else:
            print 'hola4'
            self.send_packet(datapath, ofproto.OFPP_FLOOD, pkt)



        # Creamos el conjunto de acciones: FLOOD

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

