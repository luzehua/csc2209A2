
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define NAT_INT_INTF "eth1"
#define NAT_EXT_INTF "eth2"

#define MIN_NAT_PORT 1024
#define MAX_NAT_PORT 65535

typedef enum {
    nat_mapping_icmp,
    nat_mapping_tcp
    /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
    tcp_state_listen,
    tcp_state_syn_sent,
    tcp_state_syn_received,
    tcp_state_established,
    tcp_state_fin_wait_1,
    tcp_state_fin_wait_2,
    tcp_state_close_wait,
    tcp_state_closing,
    tcp_state_last_ack,
    tcp_state_time_wait,
    tcp_state_closed
} sr_tcp_connection_state;

struct sr_nat_connection {
    /* add TCP connection state data members here */
    uint32_t ip;
    uint32_t client_isn;
    uint32_t server_isn;
    sr_tcp_connection_state state;
    time_t last_updated;
    struct sr_nat_connection *next;
};

struct sr_nat_mapping {
    sr_nat_mapping_type type;
    uint32_t ip_int; /* internal ip addr */
    uint32_t ip_ext; /* external ip addr */
    uint16_t aux_int; /* internal port or icmp id */
    uint16_t aux_ext; /* external port or icmp id */
    time_t last_updated; /* use to timeout mappings */
    struct sr_nat_connection *conns; /* list of connections. null for ICMP */
    struct sr_nat_mapping *next;
};

void sr_nat_remove_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_mapping *prev_mapping);

void sr_nat_remove_conn(struct sr_nat *nat,
                        struct sr_nat_mapping *mapping,
                        struct sr_nat_connection *conn,
                        struct sr_nat_connection *prev_conn);


struct sr_nat {
    /* add any fields here */
    int icmp_query_timeout_interval;
    int tcp_established_idle_timeout;
    int tcp_transitory_idle_timeout;

    struct sr_nat_mapping *mappings;

    /* threading */
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
    pthread_attr_t thread_attr;
    pthread_t thread;
};


int sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext, sr_nat_mapping_type type);

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                              uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
                                             uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);


#endif