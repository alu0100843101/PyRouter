from mininet.topo import Topo

class MyTopo( Topo ):
	
	def __init__( self ):

		Topo.__init__( self )
		
		for s in range(5):
			switch = self.addSwitch( 's%s' %(s + 1))	
			host = self.addHost( 'h%s' %(s + 1))
			self.addLink(host,switch)

			if s > 0:
				self.addLink(switch,auxswitch)
			
			auxswitch = switch


topos = { 'mytopo': ( lambda: MyTopo() ) }			

