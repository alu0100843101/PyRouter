1. Ejecutar el comando en comandomininet.sh: sudo mn --custom single3.py --topo single3 --switch ovsk --controller remote --pre single3gateway.py -x
Si no quieres que se abran las terminales quita el -x 
2. En la terminal del switch s1, indicarle la version de openflow. Importante las mayúsculas y minúsculas.
ovs-vsctl set bridge s1 protocols=OpenFlow
3. En la terminal del controlador c0:
ryu-manager --verbose router.py
4. Ahora puedes probar a hacer un ping
mininet> h1 ping -c 1 h2
