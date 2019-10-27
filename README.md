
(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## Implementation

I have implemented handlePacket function with the help of several helper functions. I will go through a high-level implementation of my code and indicate
what these functions do. 

1) handlePacket 
- In this function, I checked the type of of packet arriving, and whether they were IP or ARP, I executed one of two helper functions:process_arp_packet,  process_ip_packet

2) process_arp_packet
- In this function, I determine whether the arp packet is a reply or a request. If it is a reply, I execute process_arp_reply, and if it is 
  a request, I run process_arp_request

3) process_arp_request
- This function basically creates an ARP reply from scratch while making sure to include the router's MAC address, and sends it back to the sender of the  	 request.	

4) process_arp_reply
- This function essentially takes the ARP reply packet, extracts the MAC address of destination, and stores in the ARP cache. Then, it looks at
  the buffered IPv4 packets that were not yet sent, and forwards them. Finally, it removes the request from the list.

5) process_ip_packet
- This function verifies that the checksum is correct and the length of the packet is of some minimum value. If it is, it launches the routine that 
  actually forwards the packet.

6) forward_packet
- In this function, the actual forwarding happens. First it finds the next hop ip through the routing table function lookup. Lookup is implemented using
  a longest prefix match algorithm that masks the ip and gateway address and compares them, giving preference to longer addresses. Once a next hop ip is
  found, the function looks at the ARP cache to see if the MAC address is there. If it exists, then it proceeds to handle the packet normally (insert/edit with correct headers) and finally forwards it. If the MAC address is not there, then the function sends an ARP request and buffers the IPv4 packet.

7) send_arp_request
- This function creates an ARP request from scratch and broadcasts it. 

8) periodicCheckArpRequestsandCacheEntries
- This function removes ARP requests that have been sent 5 or more times, and clears the entries that have been in the cache for over 30s.

## Problems Ran Into

Most of the issues were mainly to do with the intricacies of C++. One of the biggest concerns was being able to edit packets to have the right information without losing bits or causing off by one errors. To do this, instead of manipulating the unsigned chars directly, which would have been too expensive and error prone, I used reinterpret_cast to cast the buffer into a struct and edit the values with ease. Then, once I was done, I would cast them back to a vector. Another problem I ran into was trying to understand the ARP protocol and being able to see how MAC addresses were transmitted. For this, I read more about ARP and used print_hdrs to see the sequence of ARP requests and replies and thus could establish how the protocol worked. 


