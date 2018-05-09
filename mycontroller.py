#!/usr/bin/python
#coding=utf-8

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

# Para usar el controlador Ryu se hereda de app_manager.RyuApp
class L3Switch ( app_manager.RyuApp ):
    # Se debe especificar la Versión de openflow: V 1.3
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
		super ( L3switch, self ).__init__ ( *args, **kwargs )
        # Inicialización de tabla de direcciones MAC
        self.mac_to_port = { ('1': '00:00:00:00:00:00')
                             ('2': '00:00:00:00:00:11')
                           }

    # "set_ev_cls" especifica la clase de evento soportado y el estado
    # Existe una lista de estados predefinida
    # El nombre del evento es:
    # "ryu.controller.ofp_event.EventOFP + <OpenFlow message name>"
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Comunicación entre openflow y controlador Ryu

        # Quién emitió el mensaje
        datapath = ev.msg.datapath
        # Módulo de prototipo openflow admitido (En este caso será Version 1.3)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Se genera una coincidencia vacía para unir todos los paquetes
        match = parser.OFPMatch()
        # Se crea una instancia de acción de salida
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # Se envía el mensaje con prioridad 0 (la más baja)
        self.add_flow(datapath, 0, match, actions)

    # Método para agregar entradas de flujo
    def add_flow(self, datapath, priority, match, actions):
        # datapath define el switch de origen
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Para que la acción especificada se use inmediatamente
        # se utiliza la instrucción "OFPIT_APPLY_ACTIONS"
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # Se genera el mensaje
        # Origen, prioridad para orden de entrada, coincidencias, instrucciones
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        # Se añade una entrada a la tabla de flujo emitiendo el mensaje "mod"
        datapath.send_msg(mod)

    # Crear controlador para aceptar paquetes
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        # Quién emitió el mensaje
        datapath = ev.msg.datapath
        # Módulo de prototipo openflow admitido (En este caso será Version 1.3)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Para identificar los switches obtenemos su id
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        # Analizamos los paquetes obtenidos (pkt) ethernet (eth_pkt)
        # para saber origen (src) y destino (dst)
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        # Puerto de recepción del mensaje
        in_port = msg.match['in_port']
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # Dirección MAC de remitente (dpid) - origen (src)
        self.mac_to_port[dpid][src] = in_port

        # Si se conoce la MAC de destino se usa el puerto de destino
        # Si no, se genera una inundación
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # Si se enceuntra la MAC destino, se agrega una entrada a la tabla de flujo
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # Le damos mayor prioridad porque queremos que se evalúe antes
            self.add_flow(datapath, 1, match, actions)

        # Se emite el mensaje "OFPPacketOut"
        # Se transfieren los paquetes recibidos  se encuentre o no la MAC
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
