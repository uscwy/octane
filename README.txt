INTRODUCTION
------------

This project is a simple implementation of SDN router in Linux, which use
tun as input/output interface. 

The primary router waits on both tun interface and UDP port to receive
packet from tun interface and secondary router.
The secondary router waits only on UDP port to receive message from primary
router.

Topology:
              IP Tunnel                  UDP                   RAW Socket
tun interface <-------> primary router <------> secondary router <---->internet


  router.c      main program and primary and secondary router implementation
  tun.c         read and write operation for tun interface
  log.c         functions for output logs to log files
  config_file   A sample configuration file
  
REQUIREMENTS
-------------
Linux with tun support

CRITICAL FUNCTIONS:
--------------------
router.c
packet_input      handle input packet, searching flow table and deliver to the next
handle_rawsocket  secondary router reads packet from raw socket
handle_tun        primary router reads packet from tun interface
handle_internal   handle internal packets between routers
handle_timer      handle timer event for retransimit queue
rule_send         primary router send flow entry to secondary router
rule_install      insert flow entry into local flow table
find_flow_entry   search flow table for given pattern
router_process    main loop of primary/secondary routers
create_routers    fork child process for secondary routers
get_conf          phrase configure file


MAINTAINER
------------

Yong Wang <yongw@usc.edu>

