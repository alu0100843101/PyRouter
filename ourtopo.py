################################################################################
##### PROYECTO FINAL DE LABORATORIO DE REDES EN INGENIERÍA DE COMPUTADORES #####
############## SDN: TOPOLOGÍA EN ÁRBOL PARA MININET USANDO PYTHON ##############
################## CON 1 CABECERA, N NODOS Y H HOSTS POR NODO ##################
################################################################################

from mininet.topo import Topo

class ourTopo ( Topo ):

    # Por defecto se instancia la clase con 2 nodos y 5 hosts por cada uno
    def __init__( self, nnodos=2, nhosts=5):

        # Llama al constructor de la clase de la que hereda
        # Topo.__init__ ( self )
        super(ourTopo, self).__init__()

        # Instancia la cabecera
        header = self.addHost('HEADER')

        # Cada nodo, crea un link con la cabecera
        for n in range(0, nnodos):
            nodo = self.addSwitch('S%s' %n)
            self.addLink(header, nodo)

            # Cada nodo tiene enlaces con H hosts
            for h in range(0, nhosts):
                host = self.addHost('H%s' % (n*nnodos+h))
                self.addLink(host, nodo)

topos = { 'ourtopo': ( lambda nnodos, nhosts: ourTopo ( nnodos, nhosts ) ) }
