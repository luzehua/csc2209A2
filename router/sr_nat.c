
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_router.h"
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>

int next_tcp_port = 0;
int next_icmp_port = 0;

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

    assert(nat);

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

    /* Initialize timeout thread */

    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

    nat->mappings = NULL;
    /* Initialize any variables here */
    nat->incoming_SYNs = NULL;

    next_tcp_port = MIN_NAT_PORT;
    next_icmp_port = MIN_NAT_PORT;

    return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

    pthread_mutex_lock(&(nat->lock));

    /* free nat memory here */
    struct sr_nat_mapping *mapping = nat->mappings;
    while (mapping) {
        struct sr_nat_mapping *prev_mapping = mapping;
        mapping = mapping->next;
        free(prev_mapping);
    }

    struct sr_nat_tcp_syn *incoming = nat->incoming_SYNs;
    while (incoming)
    {
        struct sr_nat_tcp_syn *prev_incoming = incoming;
        incoming = incoming->next;
        free(prev_incoming);
    }

    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) &&
           pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
    struct sr_nat *nat = (struct sr_nat *) nat_ptr;
    while (1) {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));

        time_t currtime = time(NULL);

        /* handle periodic tasks here */

        /* Handle inbound SYNs */
        struct sr_nat_tcp_syn *prev_inbound = NULL;
        struct sr_nat_tcp_syn *curr_inbound = nat->incoming_SYNs;
        while (curr_inbound) {
            /* do not respond to unsolicited inbound SYN packet for at least 6 seconds */
            if (difftime(currtime, curr_inbound->last_received) > 6) {
                struct sr_nat_mapping *mapping = sr_nat_lookup_external(nat, curr_inbound->port, nat_mapping_tcp);
                if (!mapping) {
                    handle_icmp_messages(nat->sr, curr_inbound->packet, curr_inbound->len, icmp_dest_unreachable,
                                         icmp_unreachable_port);
                }

                /* remove the syn */
                if (prev_inbound) { /* not linked list head */
                    prev_inbound->next = curr_inbound->next;
                    free(curr_inbound->packet);
                    free(curr_inbound);
                    curr_inbound = prev_inbound->next;
                } else { /* head */
                    nat->incoming_SYNs = curr_inbound->next;
                    free(curr_inbound->packet);
                    free(curr_inbound);
                    curr_inbound = nat->incoming_SYNs;
                }

            } else {
                prev_inbound = curr_inbound;
                curr_inbound = curr_inbound->next;
            }
        }



        pthread_mutex_unlock(&(nat->lock));
    }
    return NULL;
}

/* Custom: add the inbound TCP SYN connection */
void add_inbound_syn(struct sr_nat *nat, uint32_t src_ip, uint16_t src_port, uint8_t *packet, unsigned int len) {

    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_tcp_syn *cur_inbound = nat->incoming_SYNs;

    /* traverse all cur_inbound SYNs */
    while (cur_inbound) {
        /* check whether SYN existed*/
        if ((cur_inbound->ip == src_ip) && (cur_inbound->port == src_port)) {
            return;
        }
        cur_inbound = cur_inbound->next;
    }

    /* construct the SYN */
    cur_inbound = (struct sr_nat_tcp_syn *) malloc(sizeof(struct sr_nat_tcp_syn));
    cur_inbound->ip = src_ip;
    cur_inbound->port = src_port;
    cur_inbound->packet = (uint8_t *) malloc(len);
    memcpy(cur_inbound->packet, packet, len);
    cur_inbound->len = len;
    cur_inbound->last_received = time(NULL);

    /* Add as the head of cur_inbound list */
    /* avoid the corner case when linked list is empty */
    cur_inbound->next = nat->incoming_SYNs;
    nat->incoming_SYNs = cur_inbound;

    pthread_mutex_unlock(&(nat->lock));
}

/* Custom: Removes a mapping from the linked list */
void sr_nat_remove_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_mapping *prev_mapping) {
    pthread_mutex_lock(&(nat->lock));

    if (!prev_mapping) {
        /* current mapping is the head of linked list */
        nat->mappings = mapping->next;
    } else {
        prev_mapping->next = mapping->next;
    }

    struct sr_nat_connection *conn = mapping->conns;
    while (conn) {
        free(conn);
        conn = conn->next;
    }

    free(mapping);

    pthread_mutex_unlock(&(nat->lock));
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext, sr_nat_mapping_type type) {

    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *copy = NULL;

    struct sr_nat_mapping *mapping = nat->mappings;

    while (mapping) {
        if (mapping->type == type && mapping->aux_ext == aux_ext) {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

            break;
        }
        mapping = mapping->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                              uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *copy = NULL;
    struct sr_nat_mapping *mapping = nat->mappings;

    while (mapping) {
        /* go through the linked list mapping table */
        if (mapping->ip_int == ip_int && mapping->type == type && mapping->aux_int == aux_int) {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

            break;
        }
        mapping = mapping->next;
    }
    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
                                             uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

    pthread_mutex_lock(&(nat->lock));
    /* handle insert here, create a mapping, and then return a copy of it */

    /* See if it already exists */
    struct sr_nat_mapping *mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
    if (mapping) {
        return mapping;
    }

    mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

    mapping->ip_int = ip_int;
    /* TODO: double check ip_ext */
    mapping->ip_ext = 0;
    mapping->aux_int = aux_int;
    mapping->type = type;
    mapping->last_updated = time(NULL);
    mapping->conns = NULL;

    /* TODO: double check the port num*/
    switch (type) {
        case nat_mapping_icmp: {
            mapping->aux_ext = next_icmp_port++;
            if (next_icmp_port >= MAX_NAT_PORT) {
                next_icmp_port = MIN_NAT_PORT;
            }
            break;
        }

        case nat_mapping_tcp: {
            mapping->aux_ext = next_tcp_port++;
            if (next_tcp_port >= MAX_NAT_PORT) {
                next_tcp_port = MIN_NAT_PORT;
            }
            break;
        }
    }

    /* Add new mapping as the head of linked list */
    mapping->next = nat->mappings;
    nat->mappings = mapping;

    /* Make a copy for thread safety */
    struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));


    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Custom: finds a connection from a mapping's list */
struct sr_nat_connection *sr_nat_get_conn(struct sr_nat_mapping *mapping, uint32_t ip) {

    struct sr_nat_connection *conn = mapping->conns;
    struct sr_nat_connection *copy = NULL;

    /* traverse connections */
    while (conn) {
        if (conn->ip == ip) {
            copy = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
            memcpy(copy, conn, sizeof(struct sr_nat_connection));
            break;
        }
        conn = conn->next;
    }

    return copy;

    return NULL;
}

/* Custom: inserts a connection to a mapping's list */
struct sr_nat_connection *sr_nat_add_conn(struct sr_nat_mapping *mapping, uint32_t ip) {
    struct sr_nat_connection *conn = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
    memset(conn, 0, sizeof(struct sr_nat_connection));

    conn->ip = ip;
    conn->state = tcp_state_closed;
    conn->last_updated = time(NULL);

    /* Add as head of linked list */
    conn->next = mapping->conns;
    mapping->conns = conn;

    return conn;
}

/* Custom: Removes a connection from the linked list */
void sr_nat_remove_conn(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_connection *conn,
                        struct sr_nat_connection *prev_conn) {
    pthread_mutex_lock(&(nat->lock));

    if (!prev_conn) {
        /* head of linked list */
        mapping->conns = conn->next;
    } else {
        prev_conn->next = conn->next;
    }

    free(conn);

    pthread_mutex_unlock(&(nat->lock));
}