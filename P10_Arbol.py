from mininet.topo import Topo

class MyTopo( Topo ):
	
	nswitch = 0

	def __init__( self ):

		Topo.__init__( self )
		switch = self.addSwitch( 's0' )
		
		self.create_switch(switch,3)

		self.nswitch = 0;

	def create_switch( self,switch, level ):
		level-=1
		self.nswitch+=1

		switch1 = self.addSwitch( 's%s' %self.nswitch )
		
		if(level == 1):
			host1 = self.addHost( 'h%s' %self.nswitch)
			self.addLink(switch1,host1)

		self.nswitch+=1
		switch2 = self.addSwitch( 's%s' %self.nswitch)

		if(level == 1):
			host2 = self.addHost( 'h%s' %self.nswitch)
			self.addLink(switch2,host2)


		self.addLink(switch, switch1)
		self.addLink(switch, switch2)

		

		if(level > 1):
			
			self.create_switch(switch1,level)
			self.create_switch(switch2,level)
					

topos = { 'mytopo': ( lambda: MyTopo() ) }			


