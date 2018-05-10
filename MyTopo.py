from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):
	#We can use --mac option to put
	#the hardware directions in Hosts
	#and Switches

        # Initialize topology
        Topo.__init__( self )

        controller = L2Forwarding();

        # Add hosts and switches
        leftHost = self.addHost( 'h1', mac='00:00:00:00:00:01' )
        host = self.addHost( 'h2', mac='00:00:00:00:00:02' )
        rightHost = self.addHost( 'h3', mac='00:00:00:00:00:03' )

        switch = self.addSwitch( 's1', mac='00:00:00:00:01:00' )

        # Add links
        self.addLink( leftHost, switch )
        self.addLink( host, switch )
        self.addLink( switch, rightHost )

	print "*** Starting network"
	#self.build()
	#s1.start( [c1] )
	#c1.start()

	print "*** Running CLI"
	#CLI( self )
	print "*** Stopping network"
	#self.stop()

#if __name__ == '__main__':
 #   setLogLevel( 'mytopo' )
  #  MyTopo()

topos = { 'mytopo': ( lambda: MyTopo() ) }
