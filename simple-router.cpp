/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <algorithm>
#include <bitset>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <iterator>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::process_arp_reply(arp_hdr* arp_packet_hdr, const Interface* iface)
{
  std::cerr << "Processing ARP reply..." << std::endl;
  // extract source hardware address 
  std::vector<unsigned char> target_mac (ETHER_ADDR_LEN);
  std::copy(std::begin(arp_packet_hdr->arp_sha), std::end(arp_packet_hdr->arp_sha), target_mac.begin());

  std::cerr << "The MAC address obtained from the reply is: " << macToString(target_mac) << std::endl;

  uint32_t target_ip = arp_packet_hdr->arp_sip;

  auto arp_req = m_arp.insertArpEntry(target_mac, target_ip);

  if(arp_req == nullptr)
  {
    std::cerr << "Failed to create ARP entry. " << std::endl;
  }
  std::list<PendingPacket>::iterator pp_it;
  for(pp_it = (arp_req->packets).begin(); pp_it != (arp_req->packets).end(); pp_it++)
  {
    std::cerr << "I'm a pending packet! " << std::endl;
    std::copy(target_mac.begin(), target_mac.end(), (*pp_it).packet.begin());

    //convert the ip header of the packet to a struct
    std::vector<unsigned char> ip_hdr_vec (sizeof(ip_hdr));
    std::copy((*pp_it).packet.begin() + sizeof(ethernet_hdr), (*pp_it).packet.begin() + sizeof(ethernet_hdr) + sizeof(ip_hdr), ip_hdr_vec.begin());

    ip_hdr* ip_packet_hdr = reinterpret_cast<ip_hdr*>(ip_hdr_vec.data());

    //update values
    uint8_t ttl = ip_packet_hdr->ip_ttl;
    ip_packet_hdr->ip_ttl = ttl - 1;
    ip_packet_hdr->ip_sum = 0;
    uint16_t new_checksum = cksum(ip_packet_hdr, sizeof(ip_hdr));
    ip_packet_hdr->ip_sum = new_checksum;

    //convert struct into a vector for sending
    auto const ip_ptr = reinterpret_cast<unsigned char*> (ip_packet_hdr);
    std::vector<unsigned char> ip_vec (ip_ptr, ip_ptr + sizeof(ip_hdr));

    //copy the vector containing ip header bytes back into the packet (after the ethernet header)
    std::copy(ip_vec.begin(), ip_vec.end(), (*pp_it).packet.begin() + sizeof(ethernet_hdr));

    //std::cerr << "Checking to see if the headers are correct" << std::endl;
    //print_hdrs((*pp_it).packet);

    //send the pending packet
    sendPacket((*pp_it).packet, (*pp_it).iface);

    //Destroy the ARP Request
    m_arp.removeRequest(arp_req);
    
  }
  

}

void
SimpleRouter::process_arp_request(arp_hdr* arp_packet_hdr, const Interface* iface)
{
  std::cerr << "Processing ARP request..." << std::endl;
  /* First we need to check the IP address of the ARP packet */
  uint32_t target_ip = arp_packet_hdr->arp_tip;
  //std::cerr << "This is the target IP: " << target_ip << " vs " << ipToString(arp_packet_hdr->arp_tip) << std::endl;

  const Interface* target_iface = findIfaceByIp(target_ip);

  if(target_iface != nullptr) /* target ip matches one of our router's ip's*/
  {
    std::cerr << "Responding to ARP request..." << std::endl; 
    //* Create ethernet struct *//
    ethernet_hdr ehdr;
    ethernet_hdr* arp_ehdr = &ehdr;

    // copy source MAC address and add as destination hardware address
    std::copy(std::begin(arp_packet_hdr->arp_sha), std::end(arp_packet_hdr->arp_sha), std::begin(arp_ehdr->ether_dhost));
    //* copy router's MAC address as source hardware address *// 
    std::copy((target_iface->addr).begin(), (target_iface->addr).end(), std::begin(arp_ehdr->ether_shost));
    //* assign ethernet struct type as ARP *// 
    arp_ehdr->ether_type = htons(ethertype_arp);

    //* Create ARP struct *//
    arp_hdr arp_response_hdr;
    arp_hdr* arp_resp_hdr = &arp_response_hdr;

    //*assign extraneous details *//
    arp_resp_hdr->arp_hrd = arp_packet_hdr->arp_hrd;
    arp_resp_hdr->arp_pro = arp_packet_hdr->arp_pro;
    arp_resp_hdr->arp_hln = arp_packet_hdr->arp_hln;
    arp_resp_hdr->arp_pln = arp_packet_hdr->arp_pln;
    //* assign opcode *//
    arp_resp_hdr->arp_op = htons(arp_op_reply);
    //* copy router's MAC address as sender hardware address *//
    std::copy((target_iface->addr).begin(), (target_iface->addr).end(), std::begin(arp_resp_hdr->arp_sha));
    //* copy router's IP address as sender IP address *//
    arp_resp_hdr->arp_sip = target_iface->ip;
    //* copy source MAC address as target hardware address *//
    std::copy(std::begin(arp_packet_hdr->arp_sha), std::end(arp_packet_hdr->arp_sha), std::begin(arp_resp_hdr->arp_tha));
    //* copy source IP address as target IP address *//
    arp_resp_hdr->arp_tip = arp_packet_hdr->arp_sip;

    /* convert the structs into vectors for sending */
    auto const eth_ptr = reinterpret_cast<unsigned char*> (&ehdr);
    auto const arp_ptr = reinterpret_cast<unsigned char*> (&arp_response_hdr);

    std::vector<unsigned char> eth_vec (eth_ptr, eth_ptr + sizeof(ethernet_hdr));
    std::vector<unsigned char> arp_vec (arp_ptr, arp_ptr + sizeof(arp_hdr));
    /* create a big vector to send the data in */
    std::vector<unsigned char> buf (sizeof(ethernet_hdr) + sizeof(arp_hdr));
    /* copy necessary data into big vector */
    std::copy(eth_vec.begin(), eth_vec.end(), buf.begin());
    std::copy(arp_vec.begin(), arp_vec.end(), buf.begin() + sizeof(ethernet_hdr));

    //print_hdrs(buf);
    /* send packet */
    sendPacket(buf, (target_iface->name));
  }
  else
    std::cerr << "ARP request received, but not for this router. Ignoring." << std::endl;

}

void
SimpleRouter::send_arp_request(uint32_t ip, const Interface* iface)
{
  std::cerr << "Sending ARP request..." << std::endl;
  // Create ethernet struct
  ethernet_hdr ehdr;
  ethernet_hdr* arp_ehdr = &ehdr;

  // copy source MAC address
  std::copy((iface->addr).begin(), (iface->addr).end(), std::begin(arp_ehdr->ether_shost));

  //create broadcast vector
  std::vector<unsigned char> broadcast (ETHER_ADDR_LEN, 255);
  //copy to destination MAC address
  std::copy(broadcast.begin(), broadcast.end(), std::begin(arp_ehdr->ether_dhost));
  //* assign ethernet struct type as ARP *// 
  arp_ehdr->ether_type = htons(ethertype_arp);

  //* Create ARP struct *//
  arp_hdr arp_request_hdr;
  arp_hdr* arp_req_hdr = &arp_request_hdr;

  // extraneous details
  arp_req_hdr->arp_hrd = htons(arp_hrd_ethernet);
  arp_req_hdr->arp_pro = htons(ethertype_ip);
  arp_req_hdr->arp_hln = 0x06;
  arp_req_hdr->arp_pln = 0x04;
  //assign opcode
  arp_req_hdr->arp_op = htons(arp_op_request);
  // copy router MAC address as sender hardware address
  std::copy((iface->addr).begin(), (iface->addr).end(), std::begin(arp_req_hdr->arp_sha));
  // copy router's IP address as sender IP address
  arp_req_hdr->arp_sip = iface->ip;
  // create zero vector
  std::vector<unsigned char> zero_vec (ETHER_ADDR_LEN, 0);
  // zero out destination hardware address since we don't know it
  std::copy(zero_vec.begin(), zero_vec.end(), std::begin(arp_req_hdr->arp_tha));
  //copy ip to arp target ip
  arp_req_hdr->arp_tip = ip;

  // now convert the vectors into structs
  auto const eth_ptr = reinterpret_cast<unsigned char*> (&ehdr);
  auto const arp_ptr = reinterpret_cast<unsigned char*> (&arp_request_hdr);

  std::vector<unsigned char> eth_vec (eth_ptr, eth_ptr + sizeof(ethernet_hdr));
  std::vector<unsigned char> arp_vec (arp_ptr, arp_ptr + sizeof(arp_hdr));
  /* create a big vector to send the data in */
  std::vector<unsigned char> buf (sizeof(ethernet_hdr) + sizeof(arp_hdr));
  /* copy necessary data into big vector */
  std::copy(eth_vec.begin(), eth_vec.end(), buf.begin());
  std::copy(arp_vec.begin(), arp_vec.end(), buf.begin() + sizeof(ethernet_hdr));

  std::cerr << "Check to see that the ARP packet was made correctly: " << std::endl;
  //print_hdrs(buf);

  sendPacket(buf, (iface->name));




}

void
SimpleRouter::forward_packet(std::vector<unsigned char>& packet, uint32_t target_ip, const Interface* iface)
{
  std::cerr << "Forwarding in progress..." << std::endl;
  try
  {
    RoutingTableEntry ip_route = m_routingTable.lookup(target_ip);
    uint32_t next_hop_ip = ip_route.gw;

    //* Check whether next_hop_ip is in the ARP cache *//
    auto mac_arp_entry = m_arp.lookup(next_hop_ip);

    const Interface* outgoing_iface = findIfaceByName(ip_route.ifName);

    // debugging: when done, replace the ip with with 'next_hop_ip' in 1) send_arp_request  2) queueRequest
    //uint32_t fake_ip = next_hop_ip - 38; //change a legitimate IP into something nonsensical for testing


    //* Check whether a MAC address has been found or not *//
    if(mac_arp_entry == nullptr)
    {
      std::cerr << "Unable to find MAC address of next hop IP. Preparing ARP request..." << std::endl;
      // zero out dest hardware addr before queuing 
      std::vector<unsigned char> zero_vec (ETHER_ADDR_LEN, 0);
      std::copy(zero_vec.begin(), zero_vec.end(), packet.begin());
      // update source hardware address 
      std::copy((outgoing_iface->addr).begin(), (outgoing_iface->addr).end(), packet.begin() + ETHER_ADDR_LEN);

      std::cerr << "Checking whether ethernet overwrites were successful: " << std::endl;
      //print_hdrs(packet);

      // pointer to ArpRequest generated by queuing the packet
      auto arp_req = m_arp.queueRequest(next_hop_ip, packet, (outgoing_iface->name));

    
      send_arp_request(next_hop_ip, outgoing_iface);

      //Update parameters since we sent an Arp Request
      arp_req->nTimesSent = 1;
      arp_req->timeSent = steady_clock::now();


    }
    else
    {
      std::cerr << "Found MAC address of next hop IP. Handling IP packet..." << std::endl;
      //update destination MAC address
      std::copy((mac_arp_entry->mac).begin(), (mac_arp_entry->mac).end(), packet.begin());
      //update source MAC address
      std::copy((outgoing_iface->addr).begin(), (outgoing_iface->addr).end(), packet.begin() + ETHER_ADDR_LEN);

      //convert IP header to a struct 
      std::vector<unsigned char> ip_hdr_vec (sizeof(ip_hdr));
      std::copy(packet.begin() + sizeof(ethernet_hdr), packet.begin() + sizeof(ethernet_hdr) + sizeof(ip_hdr), ip_hdr_vec.begin());
      ip_hdr* ip_packet_hdr = reinterpret_cast<ip_hdr*>(ip_hdr_vec.data());

      //update values
      uint8_t ttl = ip_packet_hdr->ip_ttl;
      ip_packet_hdr->ip_ttl = ttl - 1;
      ip_packet_hdr->ip_sum = 0;
      uint16_t new_checksum = cksum(ip_packet_hdr, sizeof(ip_hdr));
      ip_packet_hdr->ip_sum = new_checksum;

      //convert struct into a vector for sending
      auto const ip_ptr = reinterpret_cast<unsigned char*> (ip_packet_hdr);
      std::vector<unsigned char> ip_vec (ip_ptr, ip_ptr + sizeof(ip_hdr));

      //copy the vector containing ip header bytes back into the packet (after the ethernet header)
      std::copy(ip_vec.begin(), ip_vec.end(), packet.begin() + sizeof(ethernet_hdr));

      //std::cerr << "Checking if the ethernet frame is correct before forwarding: " << std::endl;
      //print_hdrs(packet);

      sendPacket(packet, (outgoing_iface->name));


    }

  }
  catch(std::exception &e)
  {
    std::cerr << "Next hop IP was unable to be found: " << e.what() << std::endl;
  }

}




void
SimpleRouter::process_ip_packet(std::vector<unsigned char>& packet, const Interface* iface)
{
  std::cerr << "Processing IP packet..." << std::endl;

  std::vector<unsigned char> ip_packet_vec (sizeof(ip_hdr));

  std::vector<unsigned char>::const_iterator ip_it;
  ip_it = packet.begin();
  std::copy(ip_it + sizeof(ethernet_hdr), ip_it + sizeof(ethernet_hdr) + sizeof(ip_hdr), ip_packet_vec.begin());

  ip_hdr* ip_packet_hdr = reinterpret_cast<ip_hdr*>(ip_packet_vec.data());

  //* verify checksum *//
  uint16_t incoming_sum = ip_packet_hdr->ip_sum;
  ip_packet_hdr->ip_sum = 0;

  uint16_t calculated_sum = cksum(ip_packet_hdr, sizeof(ip_hdr));

  if((calculated_sum == incoming_sum) && (ip_packet_hdr->ip_len > sizeof(ip_hdr)))
  {
    std::cerr << "Checksum passed!" << std::endl;

    uint32_t target_ip = ip_packet_hdr->ip_dst;
    const Interface* target_iface = findIfaceByIp(target_ip);
    if(target_iface == nullptr)
    {
      std::cerr << "Destination IP address is not the router's, so forwarding begins..." << std::endl;
      forward_packet(packet, target_ip, iface);
    }
    else
      std::cerr << "This packet was addressed to the router. Ignoring." << std::endl;
  }
  else
    std::cerr << "Checksum did not match or packet is too small. Ignoring." << std::endl;
}


void
SimpleRouter::process_arp_packet(std::vector<unsigned char>& packet, const Interface* iface)
{
  std::cerr << "Processing ARP packet..." << std::endl;

  std::vector<unsigned char> arp_packet_vec (sizeof(arp_hdr));  /*create vector to copy ARP packet into */

  std::vector<unsigned char>::const_iterator arp_it;
  arp_it = packet.begin(); /*Initialize iterator to after ethernet stuff */

  /*copy ARP packet alone into the vector */
  std::copy(arp_it + sizeof(ethernet_hdr), arp_it + sizeof(ethernet_hdr) + sizeof(arp_hdr), arp_packet_vec.begin()); 


  arp_hdr* arp_packet_hdr = reinterpret_cast<arp_hdr*>(arp_packet_vec.data());

  //If ARP request:
  //std::cerr << "ARP Packet OPcode" << ntohs(arp_packet_hdr->arp_op) << "and" << arp_op_request << std::endl;
  if(ntohs(arp_packet_hdr->arp_op) == arp_op_request)
  {
    //std::cerr << "REACHED PROCESS ARP REQUEST" << std::endl;
    process_arp_request(arp_packet_hdr, iface);
  }
  else if(ntohs(arp_packet_hdr->arp_op) == arp_op_reply) /* If ARP reply */
  {
    //std::cerr << "REACHED PROCESS ARP REPLY" <<std::endl;
    process_arp_reply(arp_packet_hdr, iface);
  }
  else
    std::cerr << "Unrecognized ARP packet received. Neither request nor reply, dropping!" << std::endl;


}

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // copy packet into vector
  std::vector<unsigned char> packet_vec (packet.size());
  std::copy(packet.begin(), packet.end(), packet_vec.begin());
  
  /* debugging */
  print_hdrs(packet_vec);

 
  std::vector<unsigned char> eth_header_vec (sizeof(ethernet_hdr)); /*create a vector to copy the ethernet header into*/

  std::copy(packet_vec.begin(), packet_vec.begin() + sizeof(ethernet_hdr), eth_header_vec.begin()); /*Copy ethernet header into said vector */

  ethernet_hdr* eth_hdr = reinterpret_cast<ethernet_hdr*>(eth_header_vec.data()); /* Cast vector to an actual eth_hdr struct */
 //* debugging *//

  /* need to check for either broadcast DA or our address being the DA of this frame */
  if(ntohs(eth_hdr->ether_type) == ethertype_arp) /*If the ethernet frame is ARP*/
  {
    std::cerr << "ARP packet received." << std::endl;
    process_arp_packet(packet_vec, iface);     
  }
  else if(ntohs(eth_hdr->ether_type) == ethertype_ip) /* If it's IP */
  {
    std::cerr << "IP packet received." << std::endl;
    process_ip_packet(packet_vec, iface);
  }
  else
    std::cerr << "Unknown packet type received, dropped!" << std::endl;

  

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
