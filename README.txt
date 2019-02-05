INTRODUCTION
------------

This project is a simple implementation of SDN router in Linux, which use
tun as input/output interface. 

The primary router waits on both tun interface and UDP port to receive
packet from tun interface and secondary router.
The primary router waits only on UDP port to receive message from primary
router.

Topology:
                Tunnel                    UDP
tun interface <-------> primary router <--------> secondary router


  router.c      main program and primary and secondary router implementation
  tun.c         read and write operation for tun interface
  log.c         functions for output logs to log files
  config_file   A sample configuration file
  
REQUIREMENTS
-------------
Linux with tun support


MAINTAINER
------------

Yong Wang <yongw@usc.edu>

