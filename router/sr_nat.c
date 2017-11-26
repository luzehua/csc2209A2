
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
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

    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) &&
           pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
    struct sr_nat *nat = (struct sr_nat *) nat_ptr;
    while (1) {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));

        time_t curtime = time(NULL);

        /* handle periodic tasks here */
        /* Remove timed out mappings */
        struct sr_nat_mapping *prev_mapping = NULL;
        struct sr_nat_mapping *mapping = nat->mappings;
        while (mapping) {
            switch (mapping->type) {
                case nat_mapping_icmp: {
                    /* ICMP query timeout */
                    if (mapping->last_updated + nat->icmp_query_timeout_interval > curtime) {
                        sr_nat_remove_mapping(nat, mapping, prev_mapping);
                    }
                    break;
                }

                case nat_mapping_tcp: {

                    struct sr_nat_connection *conn = mapping->conns;
                    while (conn) {
                        /* TODO: add state check in conns struct  */
                        if (mapping->conns) {
                            /* TCP Established Idle Timeout */
                            if (mapping->last_updated + nat->tcp_established_idle_timeout > curtime) {
                                sr_nat_remove_mapping(nat, mapping, prev_mapping);
                            }
                        } else {
                            /* TCP Transitory Idle Timeout */
                            if (mapping->last_updated + nat->tcp_transitory_idle_timeout > curtime) {
                                sr_nat_remove_mapping(nat, mapping, prev_mapping);
                            }
                        }


                    }

                    break;
                }
            }

            prev_mapping = mapping;
            mapping = mapping->next;
        }


        pthread_mutex_unlock(&(nat->lock));
    }
    return NULL;
}

/* Custom: Removes a mapping from the linked list */
void sr_nat_remove_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_mapping *prev_mapping) {
    pthread_mutex_lock(&(nat->lock));
    if (!prev_mapping) {
        /* mapping was the head */
        nat->mappings = mapping->next;
    } else {
        prev_mapping->next = mapping->next;

        /* TODO: free mapping */
    }
    pthread_mutex_unlock(&(nat->lock));
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext, sr_nat_mapping_type type) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL;

    struct sr_nat_mapping *mapping = nat->mappings;

    while (mapping) {
        if (mapping->type == type && mapping->aux_ext == aux_ext) {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

            mapping->last_updated = time(NULL);
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

    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy = NULL;

    struct sr_nat_mapping *mapping = nat->mappings;

    while (mapping) {
        if (mapping->type == type && mapping->aux_ext == aux_int) {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

            mapping->last_updated = time(NULL);
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
//    struct sr_nat_mapping *mapping = NULL;
    struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->type = type;
    mapping->last_updated = time(NULL);
    mapping->conns = NULL;

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
    /* TODO: check the range of valid port*/

    mapping->next = nat->mappings;
    nat->mappings = mapping;


    pthread_mutex_unlock(&(nat->lock));
    return mapping;
}

/* Custom: finds a connection from a mapping's list */
struct sr_nat_connection *sr_nat_get_conn(struct sr_nat_mapping *mapping, uint32_t ip) {
    struct sr_nat_connection *conn = mapping->conns;

    while (conn) {
        if (conn->ip == ip) {
            return conn;
        }

        conn = conn->next;
    }

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
        /* conn was the head */
        mapping->conns = conn->next;
    } else {
        prev_conn->next = conn->next;
    }

    free(conn);

    pthread_mutex_unlock(&(nat->lock));
}