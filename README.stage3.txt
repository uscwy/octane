a) Reused Code: No
b) Complete: Yes
c) Addressing on the way of your router: Rewriting the source address is to 
make sure the returned packet would find the correct way to the external 
interface of secondary router. Otherwise, secondary would not receive the 
returned packet.
d) Addressing on the way in to the VM: Since each interface has a ip address, we can use bind to seperate the traffic to different sockets.
e) Addressing from VM to host: Host OS would do SNAT for outgoing packets.

