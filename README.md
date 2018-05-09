## README

### LABORATORIO DE REDES EN INGENIERÍA DE COMPUTADORES
### ESIIT - UNIVERSIDAD DE LA LAGUNA

#### GRUPO 3:
#### MARTÍN BELDA SOSA
#### ADÁN DE LA ROSA LUGO
#### ANDREA PÉREZ QUINTANA

## HERRAMIENTAS:

** Mininet V 3.6
** Openflow V 1.3
** Ryu
** Python V 2.7

## SOBRE EL PROYECTO:

** Mininet dispone de cuatro topologías diferentes que podemos usar: "single",
"linear", "tree" y "custom".

  - Single: Un switch conectado a N hosts: $sudo mn --topo single,N
  - Linear: Cada switch (N switches) se conecta con otro de forma lineal y cada
  switch tiene un host: $sudo mn --topo linear,N
  - Tree: Topología en árbol con profundidad N y anchura M:
  $sudo mn --topo tree,depth=n,fanout=m
  - Custom: Crear un archivo en python con su topología:
  $sudo mn --custom mytopo.py --topo mytopo
  En este caso, localización en: ./mininet/custom

Referencia: http://www.academia.edu/8826530/TUTORIAL_MININET

** mytopo.py: Script de ejemplo en python de una topología en árbol (custom).

  - Se pueden asignar de forma automática IPs y macs a los hosts mediante la
  opción --mac: $sudo mn --mac
  - El Script ha sido desarrollado a partir del script que viene al instalar
  mininet y del "walkthrough"de la referencia.

Referencia: http://mininet.org/walkthrough/#part-1-everyday-mininet-usage

** ourtopo.py: Script en python de nuestra propia topología (custom).

  - Se ha desarrollado una topología similar a la de árbol diferente a la del
  ejemplo anterior, utilizando un bucle en python, siguiendo un ejemplo de
  código publicado en github (referencia). En este caso se dispone de un nodo
  cabecera (header) y a él se conectan una serie de nodos especificados
  (switches) y a estos, una serie de hosts.
  - Para ejecutar con N nodos y H hosts por nodo:
  $sudo mn --custom ourtopo.py --topo ourtopo,N,H
  - También podemos ejecutar el comando con un test de conectividad mediante la
  opción --test pingall:
  $sudo mn --custom ourtopo.py --topo ourtopo,N,H --test pingall

Referencia: https://gist.github.com/dinigo/7980534

** mycontroller.py: Script en python del controlador usando RYU.

  - La descripción y detalles del código se encuentran en comentarios dentro del
  propio script.
  - Script desarrollado siguiendo las anotaciones de la página de referencia.
  - Ryu y Openflow se comunican mediante mensajes, éstos son controlados
  mediante eventos utilizando "ryu.controller.handler.set_ev_cls".
  - A modo resumen: Este script contiene un código en python que mediante
  los eventos generados por la comunicación entre openflow y el controlador
  simula el paso de paquetes. (Simula el funcionamiento de un switch).
  - $ryu-manager mininet/custom/mycontroller.py

Referencia: https://osrg.github.io/ryu-book/en/html/switching_hub.html
