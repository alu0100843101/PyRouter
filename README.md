# Laboratorio de Redes en Ingenería de Computadores
# ETSII - Universidad de La Laguna

## Grupo 3
* Martín Belda Sosa
* Adán de la Rosa Lugo
* Andrea Pérez Quintana

## Herramientas

* Mininet V 3.6
* Openflow V 1.3
* Ryu
* Python V 2.7

## Pasos para probar el controlador
1. Iniciar la máquina virtual con mininet y ryu instalado o el entorno que se desee
2. En caso de usar una máquina virtual, [configurarla para que se pueda acceder con ssh](https://github.com/mininet/openflow-tutorial/wiki/Set-up-Virtual-Machine#Access_VM_via_SSH)
3. Iniciar mininet con la topologia deseada, por ejemplo. Indicar que se va a usar un controlador remoto y que abra x-terms por cada componente.
```
$ sudo mn --topo single,3 --mac --switch ovsk --controller remote -x
```
4. En la terminal de cada switch, asignarle la versión 1.3 de openflow:
```
# ovs-vsctl set Bridge s1 protocols=OpenFlow13
```
5. En la terminal del controlador, iniciar el controlador, por ejemplo:
```
# ryu-manager --verbose ryu/app/example_switch_13
```
Donde ryu/app/example_switch_13 es la ruta del controlador. Esto requiere que el fichero .py sea compilado antes con:
```
mininet@mininet-vm:~$ python
Python 2.7.6 (default, Nov 23 2017, 15:49:48) 
[GCC 4.8.4] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import py_compile
>>> py_compile.compile('micontrolador.py')
```
6. Para mostrar el tráfico en un host, usar el comando tcpdump en la terminal del host, por ejemplo para el host 1:
```
# tcpdump -en -i h1-eth0
```
7. En la ventana de mininet realizar las operaciones necesarias, como enviar un ping:
```
> h1 ping -c 1 h2
```
- - - -
## Sobre el proyecto

##### Mininet dispone de cuatro topologías diferentes que podemos usar: "single",
"linear", "tree" y "custom".

- Single: Un switch conectado a N hosts:

```
$ sudo mn --topo single,N
```
- Linear: Cada switch (N switches) se conecta con otro de forma lineal y cada
switch tiene un host: 
```
$ sudo mn --topo linear,N
```
- Tree: Topología en árbol con profundidad N y anchura M:
```
$ sudo mn --topo tree,depth=n,fanout=m
```
- Custom: Crear un archivo en python con su topología:
```
$ sudo mn --custom mytopo.py --topo mytopo
```
En este caso, localización en: `~/mininet/custom`

[Referencia](http://www.academia.edu/8826530/TUTORIAL_MININET)

##### mytopo.py: Script de ejemplo en python de una topología en árbol (custom).

- Se pueden asignar de forma automática IPs y macs a los hosts mediante la
opción --mac: 
```
$sudo mn --mac
```
- El Script ha sido desarrollado a partir del script que viene al instalar
mininet y del "walkthrough"de la referencia.

[Referencia](http://mininet.org/walkthrough/#part-1-everyday-mininet-usage)

##### ourtopo.py: Script en python de nuestra propia topología (custom).

- Se ha desarrollado una topología similar a la de árbol diferente a la del
ejemplo anterior, utilizando un bucle en python, siguiendo un ejemplo de
código publicado en github (referencia). En este caso se dispone de un nodo
cabecera (header) y a él se conectan una serie de nodos especificados
(switches) y a estos, una serie de hosts.
- Para ejecutar con N nodos y H hosts por nodo:
```
$sudo mn --custom ourtopo.py --topo ourtopo,N,H
```
- También podemos ejecutar el comando con un test de conectividad mediante la
opción --test pingall:
```
$sudo mn --custom ourtopo.py --topo ourtopo,N,H --test pingall
```

[Referencia](https://gist.github.com/dinigo/7980534)

##### mycontroller.py: Script en python del controlador usando RYU.

- La descripción y detalles del código se encuentran en comentarios dentro del
propio script.
- Script desarrollado siguiendo las anotaciones de la página de referencia.
- Ryu y Openflow se comunican mediante mensajes, éstos son controlados
mediante eventos utilizando `"ryu.controller.handler.set_ev_cls".`
- A modo resumen: Este script contiene un código en python que mediante
los eventos generados por la comunicación entre openflow y el controlador
simula el paso de paquetes. (Simula el funcionamiento de un switch).
```
$ ryu-manager mininet/custom/mycontroller.py
```

[Referencia](https://osrg.github.io/ryu-book/en/html/switching_hub.html)
