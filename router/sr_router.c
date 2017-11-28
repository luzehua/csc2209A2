/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */
    if (sr->isNAT) {
        sr_nat_init(&(sr->nat));
    }

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);


    /* Interface where we received the packet*/
    struct sr_if *sr_interface = sr_get_interface(sr, interface);


    /* package without ethernet header */
    uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t));

    switch (ethertype(packet)) {

        case ethertype_arp: {


            printf("*** -> ARP packet received\n");
            sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) payload;

            /* Check it's a valid ethernet packet*/
            if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
                printf("*** -> ARP: Not an valid ethernet frame\n");
                return;
            }

            /* Check if router's interface is destination*/
            struct sr_if *destination = sr_get_interface_by_ipaddr(sr, arp_hdr->ar_tip);
            if (!destination) {
                return;
            }

            switch (ntohs(arp_hdr->ar_op)) {
                case arp_op_request: {
                    /* Reply back if its a ARP request*/
                    uint8_t *eth_request = malloc(len);
                    memcpy(eth_request, packet, len);

                    /* Ethernet header*/
                    sr_ethernet_hdr_t *request_ehdr = (sr_ethernet_hdr_t *) eth_request;

                    /* Init ethernet header, swap destination MAC and source MAC address*/
                    memcpy(request_ehdr->ether_dhost, request_ehdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(request_ehdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);

                    /* Init ARP header */
                    sr_arp_hdr_t *arp_request_hdr = (sr_arp_hdr_t *) (eth_request + sizeof(sr_ethernet_hdr_t));
                    arp_request_hdr->ar_sip = sr_interface->ip;                         /* sender IP address       */
                    arp_request_hdr->ar_tip = arp_hdr->ar_sip;                          /* target IP address       */
                    memcpy(arp_request_hdr->ar_sha, sr_interface->addr, ETHER_ADDR_LEN);/* sender MAC address      */
                    memcpy(arp_request_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);   /* target MAC address      */
                    arp_request_hdr->ar_op = htons(arp_op_reply);                       /* ARP opcode (command)    */

                    send_packet(sr, eth_request, len, sr_interface, arp_hdr->ar_sip);

                    free(eth_request);

                    break;
                }


                case arp_op_reply: {
                    printf("*** -> ARP cache reply\n");

                    struct sr_arpreq *cached = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

                    if (cached) {
                        struct sr_packet *packet = cached->packets;

                        struct sr_if *router_interface = NULL;
                        sr_ethernet_hdr_t *ethernet_hdr = NULL;

                        while (packet) {
                            router_interface = sr_get_interface(sr, packet->iface);

                            if (router_interface) {
                                /* Set src/dest MAC addresses */
                                ethernet_hdr = (sr_ethernet_hdr_t *) (packet->buf);
                                memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                                memcpy(ethernet_hdr->ether_shost, router_interface->addr, ETHER_ADDR_LEN);

                                sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                            }

                            packet = packet->next;
                        }

                        sr_arpreq_destroy(&sr->cache, cached);
                    }
                    break;
                }
            }
            break;
        }

        case ethertype_ip: {

            if (sr->isNAT) {
                handle_ip_nat(sr, packet, interface, len);
            }

            printf("*** -> IP packet received\n");

            /* IP packet */
            sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) payload;

            /* Check length and checksum */
            if (verify_ip_packet(ip_hdr) == -1) {
                return;
            }

            /* Check if router's interface is destination*/
            struct sr_if *destination = sr_get_interface_by_ipaddr(sr, ip_hdr->ip_dst);

            if (destination) {
                switch (ip_hdr->ip_p) {
                    /* ICMP messages */

                    case ip_protocol_icmp: {

                        printf("*** -> IP: An ICMP message\n");

                        if (verify_icmp_packet(payload, len) == -1) {
                            return;
                        }

                        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (payload + sizeof(sr_ip_hdr_t));


                        /* Echo reply (type 0)Sent in response to an echo request (ping) to one of the router’s interfaces. */
                        if (icmp_hdr->icmp_type == icmp_echo_request) {

                            handle_icmp_messages(sr, packet, len, icmp_echo_reply, (uint8_t) 0);
                        }
                        break;
                    }

                        /* TCP / UDP messages: drop packet and send type 3 ICMP--destination unreachable*/
                    case ip_protocol_tcp: {
                        printf("*** -> IP: TCP message, drop packet and sent ICMP destination unreachable\n");
                        handle_icmp_messages(sr, packet, len, icmp_dest_unreachable, icmp_unreachable_port);

                        break;
                    }

                    case ip_protocol_udp: {
                        printf("*** -> IP: UDP message, drop packet and sent ICMP destination unreachable\n");
                        handle_icmp_messages(sr, packet, len, icmp_dest_unreachable, icmp_unreachable_port);

                        break;
                    }
                }
            } else {
                /* Not the destination, forward packet*/
                printf("*** -> IP: Forward packet, destination not in router's interface\n");
                ip_hdr->ip_ttl--;

                /* Discard packet is time exceeded and sent out ICMP message */
                if (ip_hdr->ip_ttl == 0) {
                    printf("*** -> IP: TTL -> 0, ICMP time exceeded\n");

                    handle_icmp_messages(sr, packet, len, icmp_time_exceeded, (uint8_t) 0);

                    return;
                }

                /* recompute the checksum over the changed header before forwarding it to the next hop. */
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

                /* Implement longest prefix matching to get right entry in routing table */
                struct sr_rt *route = match_longest_prefix(sr, ip_hdr->ip_dst);

                if (!route) {
                    printf("No route found (sending ICMP net unreachable)\n");
                    handle_icmp_messages(sr, packet, len, icmp_dest_unreachable, icmp_unreachable_net);
                    return;
                }

                struct sr_if *route_intf = sr_get_interface(sr, route->interface);
                if (!route_intf) {
                    printf("No interface found with name \"%s\"", route->interface);
                    return;
                }
                send_packet(sr, packet, len, route_intf, route->gw.s_addr);
            }
            break;
        }
    }
}

/* end sr_ForwardPacket */

int verify_ip_packet(sr_ip_hdr_t *headers) {
    /* Check ip header has valid length */
    if (headers->ip_len < 20) {
        printf("*** -> IP header length invalid\n");
        return -1;
    }
    /* Verify checksum */

    uint16_t old_cksum = headers->ip_sum;
    headers->ip_sum = 0;
    /* length headers->ip_hl * 4*/
    uint16_t new_cksum = cksum(headers, sizeof(sr_ip_hdr_t));
    headers->ip_sum = old_cksum;
    if (old_cksum != new_cksum) {
        printf("IP: checksum didn't match\n");
        return -1;
    }
    return 0;
}

/* Custom method: verify TCP headers */
int verify_tcp(sr_tcp_hdr_t *header)
{
    /* Minimum size */
    if (header->offset < 5)
    {
        printf("TCP: insufficient header length\n");
        return -1;
    }

    /* Maximum size */
    if (header->offset > 15)
    {
        printf("TCP: header length too large\n");
        return -1;
    }

    /* Verify TCP checksum */
    uint16_t old_cksum = header->tcp_cksum;
    header->tcp_cksum = 0;
    uint16_t new_cksum = cksum(header, header->offset * 4);
    header->tcp_cksum = old_cksum;
    if (old_cksum != new_cksum)
    {
        printf("TCP: checksum didn't match\n");
        return -1;
    }

    return 0;
}

int verify_icmp_packet(uint8_t *payload, unsigned int len) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) payload;

    /* Verify header length is valid */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
        printf("ICMP: insufficient header length\n");
        return -1;
    }

    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (payload + sizeof(sr_ip_hdr_t));

    /* Verify ICMP checksum*/
    uint16_t old_cksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    uint16_t new_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_sum = old_cksum;
    if (old_cksum != new_cksum) {
        printf("ICMP: invalid checksum\n");
        return -1;
    }
    return 0;
}

void send_packet(struct sr_instance *sr,
                 uint8_t *packet /* lent */,
                 unsigned int len,
                 struct sr_if *interface,
                 uint32_t destip) {
    /*
    # When sending packet to next_hop_ip
    entry = arpcache_lookup(next_hop_ip)

    if entry:
        use next_hop_ip->mac mapping in entry to send the packet
        free entry
    else:
        req = arpcache_queuereq(next_hop_ip, packet, len)
        handle_arpreq(req)
    */
    struct sr_arpentry *cached = sr_arpcache_lookup(&sr->cache, destip);

    if (cached) {
        printf("*** -> ARP mapping cached, send packet out\n");
        /* send out packet */
        sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) packet;
        /* Get destination addr from cached table */
        memcpy(ethernet_hdr->ether_dhost, cached->mac, ETHER_ADDR_LEN);
        /* Get source addr MAC address from the interface that sent it */
        memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, interface->name);

        free(cached);
    } else {
        printf("*** -> Not cached, send ARP request\n");
        /* Queue ARP request */
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, destip, packet, len, interface->name);
        handle_arpreq(sr, req);
    }
}


void handle_icmp_messages(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code) {
    /* Construct ethernet and ip header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Get longest matching prefix for source */
    struct sr_rt *match_route = match_longest_prefix(sr, ip_hdr->ip_src);

    if (!match_route) {
        printf("send_icmp_msg: Routing table entry not found\n");
        return;
    }

    struct sr_if *out_interface = sr_get_interface(sr, match_route->interface);

    switch (type) {
        case icmp_echo_reply: {
            /* Update Ethernet Header source host/destination host */
            memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);

            /* Swap IP header source/destination */
            uint32_t new_dest = ip_hdr->ip_src;
            ip_hdr->ip_src = ip_hdr->ip_dst;
            ip_hdr->ip_dst = new_dest;

            /* Create ICMP header */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;

            /* Recompute ICMP Checksum */
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));

            send_packet(sr, packet, len, out_interface, match_route->gw.s_addr);

            break;
        }

            /* Type 3 or Type 11 ICMP */
        case icmp_time_exceeded:
        case icmp_dest_unreachable: {
            /* Calculate new packet length */
            unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *new_packet = malloc(new_len);

            /* Construct headers */
            sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) new_packet;
            sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t) +
                                                               sizeof(sr_ip_hdr_t));

            /* Set eth_hdr */
            memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
            new_eth_hdr->ether_type = htons(ethertype_ip);

            /* Set ip_hdr */
            new_ip_hdr->ip_v = 4;
            new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
            new_ip_hdr->ip_tos = 0;
            new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            new_ip_hdr->ip_id = htons(0);
            new_ip_hdr->ip_off = htons(IP_DF);
            new_ip_hdr->ip_ttl = INIT_TTL;
            new_ip_hdr->ip_p = ip_protocol_icmp;

            /* Port unreachable returns to sender where all else is forwarded */
            new_ip_hdr->ip_src = code == icmp_dest_unreachable ? ip_hdr->ip_dst : out_interface->ip;
            new_ip_hdr->ip_dst = ip_hdr->ip_src;

            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

            /* Set icmp_hdr */
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

            send_packet(sr, new_packet, new_len, out_interface, match_route->gw.s_addr);
            free(new_packet);
            break;
        }


    }
}

/* Custom: handles IP packet with NAT functionality */
void handle_ip_nat(struct sr_instance *sr, uint8_t *packet, char *interface, unsigned int len)
{
    printf("NAT is on!\n");

    uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)payload;

    struct sr_nat_mapping *mapping = NULL;

    if (strncmp(interface, NAT_INT_INTF, sr_IFACE_NAMELEN) == 0)
    {
        /* Internal -> external */
        printf("***IP NAT: packet from internal interface\n");

        /* Check if destined for one of the router's interfaces */
        struct sr_if *dest_is_router = sr_get_interface_by_ipaddr(sr, ip_hdr->ip_dst);

        //TODO: verify the icmp message when a internal message sent router.
        if (dest_is_router)
        {
            handle_icmp_messages(sr, packet, len, icmp_dest_unreachable, icmp_unreachable_port);
        }
        else
        {
            /* Outbound message */
            printf("***IP NAT internal: outbound message\n");

            struct sr_if *ext_intf = sr_get_interface(sr, "eth2");

            switch (ip_hdr->ip_p)
            {
                case ip_protocol_icmp:
                {
                    printf("***IP NAT internal: ICMP message\n");

                    /* Verify ICMP header */
                    if (verify_icmp_packet(packet, len) == -1)
                    {
                        return;
                    }

                    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                    /* Find NAT mapping based on ICMP id and IP source address */
                    mapping = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
                    if (!mapping)
                    {
                        mapping = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
                        mapping->ip_ext = ext_intf->ip;
                        mapping->last_updated = time(NULL);
                    }

                    /* Set ICMP id with mapping's external port number and updata chksum */
                    icmp_hdr->icmp_id = mapping->aux_ext;
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                    break;
                }

                case ip_protocol_tcp:
                {
                    printf("IP NAT internal: TCP message\n");

                    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                    /* Verify TCP header */
                    if (verify_tcp(tcp_hdr) == -1)
                    {
                        return;
                    }

                    /* Find NAT mapping based on TCP source port and IP source address */
                    mapping = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, ntohs(tcp_hdr->src_port), nat_mapping_tcp);
                    if (!mapping)
                    {
                        mapping = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, ntohs(tcp_hdr->src_port), nat_mapping_tcp);
                        mapping->ip_ext = ext_intf->ip;
                        mapping->last_updated = time(NULL);
                    }

                    pthread_mutex_lock(&(sr->nat.lock));

                    struct sr_nat_connection *conn = sr_nat_get_conn(mapping, ip_hdr->ip_dst);
                    if (!conn)
                    {
                        conn = sr_nat_add_conn(mapping, ip_hdr->ip_dst);
                    }

                    switch (conn->state)
                    {
                        case tcp_state_established:
                        {
                            /* ESTAB -> CLOSED (ACK of FIN) */
                            if (tcp_hdr->fin && tcp_hdr->ack)
                            {
                                conn->client_sn = ntohl(tcp_hdr->seq);
                                conn->state = tcp_state_closed;
                            }
                            break;
                        }

                        case tcp_state_closed:
                        {
                            /* CLOSED -> SYN_SENT */
                            if (!tcp_hdr->ack && tcp_hdr->syn && ntohl(tcp_hdr->ack) == 0)
                            {
                                conn->client_sn = ntohl(tcp_hdr->seq);
                                conn->state = tcp_state_syn_sent;
                            }
                            break;
                        }

                        case tcp_state_syn_received:
                        {
                            /* SYN_RCVD -> ESTAB (ACK of SYN) */
                            if (!tcp_hdr->syn && ntohl(tcp_hdr->seq) == conn->client_sn + 1 && ntohl(tcp_hdr->ack) == conn->server_sn + 1)
                            {
                                conn->client_sn = ntohl(tcp_hdr->seq);
                                conn->state = tcp_state_established;
                            }

                            add_inbound_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, packet, len);
                            break;
                        }

                        default:
                        {
                            break;
                        }
                    }

                    pthread_mutex_unlock(&(sr->nat.lock));

                    /* Update TCP header with mapping's external port */
                    tcp_hdr->src_port = htons(mapping->aux_ext);

                    tcp_hdr->tcp_cksum = 0;
                    tcp_hdr->tcp_cksum = verify_tcp(tcp_hdr);

                    break;
                }
            }

            /* Update IP header's source with NAT's external IP */
            ip_hdr->ip_src = ext_intf->ip;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        }
    }
    else if (strncmp(interface, NAT_EXT_INTF, sr_IFACE_NAMELEN) == 0)
    {
        /* External -> internal */
        printf("IP NAT external: external interface\n");

        /* Check if destined for one of the router's interfaces */
        struct sr_if *dest = sr_get_interface_by_ipaddr(sr, ip_hdr->ip_dst);

        if (dest)
        {
            /* Inbound message */
            printf("IP NAT external: inbound message\n");

            switch (ip_hdr->ip_p)
            {
                case ip_protocol_icmp:
                {
                    printf("IP NAT external: ICMP message\n");

                    /* Verify ICMP header */
                    if (verify_icmp_packet(packet, len) == -1)
                    {
                        return;
                    }

                    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                    /* Find NAT mapping based on ICMP id */
                    mapping = sr_nat_lookup_external(&(sr->nat), icmp_hdr->icmp_id, nat_mapping_icmp);
                    if (!mapping)
                    {
                        printf("IP NAT external: can't find ICMP mapping, dropping\n");
                        return;
                    }

                    /* Update ICMP header with mapping's internal ID */
                    icmp_hdr->icmp_id = mapping->aux_int;
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                    break;
                }

                case ip_protocol_tcp:
                {
                    printf("IP NAT external: TCP message\n");

                    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                    /* Verify TCP header */
                    if (verify_tcp(tcp_hdr) == -1)
                    {
                        return;
                    }

                    /* Restricted ports */
                    if (ntohs(tcp_hdr->dest_port) < MIN_NAT_PORT)
                    {
                        printf("IP NAT external: restricted TCP port, dropping\n");
                        handle_icmp_messages(sr, packet, len, icmp_dest_unreachable, icmp_unreachable_port);
                        return;
                    }

                    /* Find NAT mapping based on TCP destination port */
                    mapping = sr_nat_lookup_external(&(sr->nat), ntohs(tcp_hdr->dest_port), nat_mapping_tcp);
                    if (!mapping)
                    {
                        /* Add new SYN if it's a valid route */
                        if (tcp_hdr->syn)
                        {
                            struct sr_rt *rt = (struct sr_rt *)match_longest_prefix(sr, ip_hdr->ip_dst);
                            if (rt)
                            {
                                add_inbound_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->dest_port, packet, len);
                            }
                        }

                        printf("IP NAT external: can't find TCP mapping, dropping\n");
                        return;
                    }

                    pthread_mutex_lock(&(sr->nat.lock));

                    struct sr_nat_connection *conn = sr_nat_get_conn(mapping, ip_hdr->ip_src);
                    if (!conn)
                    {
                        conn = sr_nat_add_conn(mapping, ip_hdr->ip_src);
                    }

                    switch (conn->state)
                    {
                        case tcp_state_syn_sent:
                        {
                            /* SYN_SENT -> SYN_RECV */
                            if (tcp_hdr->syn)
                            {
                                if (tcp_hdr->ack && ntohl(tcp_hdr->ack) == conn->client_sn + 1)
                                {
                                    /* Simultaneous open */
                                    conn->server_sn = ntohl(tcp_hdr->seq);
                                    conn->state = tcp_state_syn_received;
                                }
                                else if (!tcp_hdr->ack && ntohl(tcp_hdr->ack) == 0)
                                {
                                    /* SYN + initial seq num of 0 */
                                    conn->server_sn = ntohl(tcp_hdr->seq);
                                    conn->state = tcp_state_syn_received;
                                }
                            }
                            break;
                        }

                        case tcp_state_syn_received:
                        {
                            add_inbound_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, packet, len);
                            break;
                        }

                        default:
                        {
                            break;
                        }
                    }

                    pthread_mutex_unlock(&(sr->nat.lock));

                    /* Update TCP header's destination port with mapping's internal port */
                    tcp_hdr->dest_port = htons(mapping->aux_int);

                    tcp_hdr->tcp_cksum = 0;
                    tcp_hdr->tcp_cksum = verify_tcp(tcp_hdr);

                    break;
                }
            }
        }
        else
        {
            printf("IP NAT external: not destined for router, dropping\n");
            return;
        }

        /* Update IP header destination with mapping's internal IP */
        ip_hdr->ip_dst = mapping->ip_int;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    }

    /* Send packet */
    if (mapping)
    {

        ip_hdr->ip_ttl--;

        /* Discard packet is time exceeded and sent out ICMP message */
        if (ip_hdr->ip_ttl == 0) {
            printf("*** -> IP: TTL -> 0, ICMP time exceeded\n");

            handle_icmp_messages(sr, packet, len, icmp_time_exceeded, (uint8_t) 0);

            return;
        }

        /* recompute the checksum over the changed header before forwarding it to the next hop. */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        /* Implement longest prefix matching to get right entry in routing table */
        struct sr_rt *route = match_longest_prefix(sr, ip_hdr->ip_dst);

        if (!route) {
            printf("No route found (sending ICMP net unreachable)\n");
            handle_icmp_messages(sr, packet, len, icmp_dest_unreachable, icmp_unreachable_net);
            return;
        }

        struct sr_if *route_intf = sr_get_interface(sr, route->interface);
        if (!route_intf) {
            printf("No interface found with name \"%s\"", route->interface);
            return;
        }
        send_packet(sr, packet, len, route_intf, route->gw.s_addr);

        free(mapping);
        return;
    }
}
