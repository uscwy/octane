a) Reused Code: No
b) Complete: Yes
c) Multiplexing: Since we replaced the source address with the interface 
address when sending packets, the returnning traffic would go directly to
that interface. Because we bind the address to our socket, all we need to
do is read from that socket.

