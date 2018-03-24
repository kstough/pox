#!/bin/sh

# https://github.com/mininet/openflow-tutorial/wiki/Learn-Development-Tools

sudo mn --topo single,3 --mac --switch ovsk --controller remote
# Create 3 virtual hosts
# Create OpenFlow switch in the kernel with 3 ports
# Connected virtual hosts to the switch
# Set the MAC address of each host equal to its IP
# Configure the OpenFlow switch to connect to a remote controller

#sudo mn --topo single,3 --controller remote --switch user
