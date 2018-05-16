# Router Openflow usando la API de Ryu (Python)

## Instalacion del entorno en linux (probado en Ubuntu 16.04)
##### Nota: si algún paso falla es recomendable averiguar por qué antes de seguir con el siguiente
1. Update
```
sudo apt update
```
* Instalar Mininet
```
sudo apt install mininet
```
*  Instalar RYU
  * Instalar dependencias
  ```
  sudo apt install gcc python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
  ```
  * Instalar Ryu
  ```
  sudo pip install ryu  
  ```



## Pasos para probar un controlador
1. Iniciar mininet con la topologia deseada, por ejemplo. Indicar que se va a usar un controlador remoto y que abra x-terms por cada componente.
```
$ sudo mn --topo single,3 --mac --switch ovsk --controller remote -x
```
2. En la terminal de cada switch, asignarle la versión 1.3 de openflow:
```
s1# ovs-vsctl set Bridge s1 protocols=OpenFlow13
```
3. En la terminal del controlador, iniciar el controlador, por ejemplo:
```
c0# ryu-manager --verbose ryu/app/example_switch_13
```
Donde ryu/app/example_switch_13 es la ruta del controlador.

4. Para mostrar el tráfico en un host, usar el comando tcpdump en la terminal del host, por ejemplo para el host 1:
```
h1# tcpdump -en -i h1-eth0
```
5. En la ventana de mininet realizar las operaciones necesarias, como enviar un ping:
```
mininet> h1 ping -c 1 h2
```
6. Para mostrar la flow table de un switch, usar el comando ovs-ofctl dump-flows. Por ejemplo para el switch 1:
```
s1# ovs-ofctl -O openflow13 dump-flows s1
```

## Pasos para probar nuestro controlador
El controlador se encuentra en el fichero `router.py`. Está inicializado para una topología en árbol con un switch y 3 hosts. Asigna una ip a cada una de las 3 interfaces del switch guardándola por pares de valor mac/ip.
La topología que se usa está en el fichero `single3.py`, que inicializa mac's, ip's y máscaras de los host. El fichero `single3gateway.py` es un script para asignar el gateway de cada host, y guardar las mac's de cada interfaz del switch en un fichero, que es abierto y leido en `router.py` para asignar los pares mac/ip. Esto se debe a que en cada ejecucion de mininet las macs asociadas a las interfaces del switch cambian y se desconoce cómo pueden asignarse unas mac fijas.
### TL;DR
1. Ejecuta el comando:
```
sudo mn --custom single3.py --topo single3 --switch ovsk --controller remote --pre single3gateway.py -x
```
Si no quieres que se abran las terminales quita el `-x`

2. En la terminal del switch s1, indicarle la version de openflow. Importante las mayúsculas y minúsculas.
```
ovs-vsctl set bridge s1 protocols=OpenFlow
```
3. En la terminal del controlador c0:
```
ryu-manager --verbose router.py
```
4. Ahora puedes probar a hacer un ping
```
mininet> h1 ping -c 1 h2
```


- - - -
## Enlaces a referencias usadas para este proyecto
* [Tabla de openflow (vídeo)](https://www.youtube.com/watch?v=-xLQHld3fPI)
* [Introducción a OpenFlow(vídeo)](https://www.youtube.com/watch?v=l25Ukkmk6Sk)
* [Documentación de openflow](http://flowgrammable.org/sdn/openflow/message-layer/)
* [El protocolo ARP (vídeo)](https://www.youtube.com/watch?v=2ydK33mPhTY)
* Tutoriales
  * [Mininet](http://mininet.org/walkthrough/)
  * [Switching hub con RYU](https://osrg.github.io/ryu-book/en/html/switching_hub.html)



## Autores
* Martín Belda Sosa
* Adán de la Rosa Lugo
* Andrea Pérez Quintana

## Herramientas

* Mininet V 3.6
* Openflow V 1.3
* Ryu
* Python V 2.7
