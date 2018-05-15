py "Añadiendo gateways"
h1 route add default gw 10.0.1.1
h2 route add default gw 10.0.2.1
h3 route add default gw 10.0.3.1
py "Gateway de h1"
h1 route -n
py "Gateway de h2"
h2 route -n
py "Gateway de h3"
h3 route -n
py "Guardando mac's del switch 1 en un fichero"
s1 ifconfig -a | grep s1-eth > macaddr.tmp
s1 awk '{print $5}' macaddr.tmp > macaddr2.tmp
