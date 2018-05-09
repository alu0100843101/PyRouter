################################################################################
##### PROYECTO FINAL DE LABORATORIO DE REDES EN INGENIERÍA DE COMPUTADORES #####
############## SDN: TOPOLOGÍA EN ÁRBOL PARA MININET USANDO PYTHON ##############
################################################################################

from mininet.topo import Topo

class MyTopo ( Topo ):

    def __init__ ( self ):

        # Nivel de inicio
        sw_level = 0

        # Llama al constructor de la clase de la que hereda
        # super(myTopo, self).__init__()
        Topo.__init__ ( self )

        # Creamos el primer Switch y a partir de él, el resto de dispositivos
        switch = self.addSwitch ( 'S0' )

        # Pasamos el primer switch y el numero de niveles que queremos
        self.createSwitch ( switch, 3 )

        self.sw_level = 0

    def createSwitch ( self, switch, level ):
        level = level-1

        self.sw_level = sw_level+1
        switch1 = self.addswitch ( 'S%s' %self.sw_level )
        if(level == 1):
			host1 = self.addHost ( 'H%s' %self.sw_level)
			self.addLink ( switch1, host1 )

        self.sw_level = sw_level+1
        switch2 = self.addswitch ( 'S%s' %self.sw_level )
        if(level == 1):
			host2 = self.addHost ( 'H%s' %self.sw_level)
			self.addLink ( switch2,host2 )

        self.addLink ( switch, switch1 )
        self.addLink ( switch1, switch2 )

topo = { 'mytopo': ( lambda: MyTopo() ) }
