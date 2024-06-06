#!/bin/bash

sudo ip xfrm policy flush
sudo ip xfrm state flush

# Remove all GRE interfaces
GREs=$(ip link show type gre | awk 'NR%2==1 {print $2}' | cut -d @ -f 1)
for GRE in ${GREs}; do
    sudo ip link del ${GRE}
    echo del ${GRE}
done

# Remove all XFRM interfaces
XFRMIs=$(ip link show type xfrm | awk 'NR%2==1 {print $2}' | cut -d @ -f 1)
for XFRMI in ${XFRMIs}; do
    sudo ip link del ${XFRMI}
    echo del ${XFRMI}
done
