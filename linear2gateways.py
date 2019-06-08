py "Añadiendo gateways"
h1 route add default gw 10.0.1.1
h2 route add default gw 10.0.2.1
py "Gateway de h1"
h1 route -n
py "Gateway de h2"
h2 route -n
