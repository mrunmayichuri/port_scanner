# port_scanner

The scanning is done by sending packets with SYN flag set to each port and listening for the replies.

The backtrack machine sends a SYN packet as if to initiate 3-way handshake, if the external router responds with a SYN/ACK packet from a particular port, it means the port is OPEN.
If the external router responds with RST packet, it means port is CLOSED.
However, if backtrack machine doesn’t receive any packet, the packet may have lost in the transmission or port has been FILTERED.
