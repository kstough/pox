#!/bin/sh

#sudo mn --custom topo-2sw-2host.py --topo mytopo --mac --switch ovsk --controller remote
#sudo mn --custom new_arch_pyt.py --topo mytopo --mac --switch ovsk --controller remote

sudo mn --custom topo-custom.py --topo mytopo --mac --switch ovsk --controller remote
