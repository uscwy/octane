a) Reused Code: No
b) Complete: Yes
c) Reliability: I use link list to implement a retransimit queue. On receiving
ACK, delete corresponding node, and use timer file descriptor to handle timeout
event together with raw sockets.
d) Chance of Failure: Since we use internal loop interface to send control msg,
it's less likely to lose packet unless there's software exception or memory 
is full.
