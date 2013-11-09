
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"

#define ACK_PKT_LEN 	 8
#define MIN_DATA_PKT_LEN 12
#define MAX_PKT_LEN 	 512
#define MAX_DATA 	 500
#define true 		 1
#define false 		 0

struct reliable_state {
  rel_t *next;			/* Linked list for traversing all connections */
  rel_t **prev;

  conn_t *c;			/* This is the connection object */

  /* Add your own data fields below this */
  struct config_common cc;
  int last_retransmit;		/* Last time packet was retransmitted or sent for the
				   first time.*/
  uint32_t last_acked;		/* Last acked packet (by other side). */
  uint32_t last_seqno;   	/* Last used sequence number (by me). */
  uint32_t last_recvd_pkt;	/* Last received packet seqno. */
  packet_t outstanding_pkt;	/* Outstanding packet (counldn't output it). */ 
  int waiting_to_output;	/* 1 if a packet is waiting for conn_output(). 
				   0 otherwise. */
  packet_t last_sent_pkt;	/* Last data packet we sent. */
  int sent_eof;
  int received_eof;
};
rel_t *rel_list;

int length_verified(packet_t* packet, size_t recvd_len);
int checksum_verified(packet_t* packet, size_t recvd_len);
void send_ack_packet(rel_t* r, int ackno);
void send_data_packet(rel_t* r, char* buf, int len, int seqno);
void close_conn_if_possible(rel_t* r);

/* Creates a new reliable protocol session, returns NULL on failure.
 * Exactly one of c and ss should be NULL.  (ss is NULL when called
 * from rlib.c, while c is NULL when this function is called from
 * rel_demux.) */
rel_t *
rel_create (conn_t *c, const struct sockaddr_storage *ss,
	    const struct config_common *cc)
{
  rel_t *r;

  r = xmalloc (sizeof (*r));
  memset (r, 0, sizeof (*r));

  if (!c) {
    c = conn_create (r, ss);
    if (!c) {
      free (r);
      return NULL;
    }
  }

  r->c = c;
  r->next = rel_list;
  r->prev = &rel_list;
  if (rel_list)
    rel_list->prev = &r->next;
  rel_list = r;

  /* Do any other initialization you need here */
  memcpy(&(rel_list->cc), cc, sizeof(struct config_common));
  rel_list->last_acked = 0x00000000;
  rel_list->last_seqno = 0x00000000;
  rel_list->last_recvd_pkt = 0x000000;
  rel_list->sent_eof = false;
  rel_list->received_eof = false; 
  rel_list->waiting_to_output = false;  
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  rel_list->last_retransmit = ts.tv_sec*1000; 
  return r;
}

void
rel_destroy (rel_t *r)
{
  if (r->next)
    r->next->prev = r->prev;
  *r->prev = r->next;
  conn_destroy (r->c);

  /* Free any other allocated memory here */
  free(r);
}


/* This function only gets called when the process is running as a
 * server and must handle connections from multiple clients.  You have
 * to look up the rel_t structure based on the address in the
 * sockaddr_storage passed in.  If this is a new connection (sequence
 * number 1), you will need to allocate a new conn_t using rel_create
 * ().  (Pass rel_create NULL for the conn_t, so it will know to
 * allocate a new connection.)
 */
void
rel_demux (const struct config_common *cc,
	   const struct sockaddr_storage *ss,
	   packet_t *pkt, size_t len)
{
}

void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
  if (!length_verified(pkt, n)) {
    return;
  }

  if (!checksum_verified(pkt, n)) {
    return;
  }

 
  if (ntohs(pkt->len) == ACK_PKT_LEN) {
    if (ntohl(pkt->ackno) - r->last_seqno == 1) {
      r->last_acked = r->last_seqno;
      if (r->sent_eof) { // This is ack'ing the EOF we sent --> check if we can close.
        close_conn_if_possible(r);
        return;
      }
      rel_read(r);
      return;
    } else { // Drop packet.
      return;
    }
  }

/* Since it passed the length check & isn't an ack packet 
   --> it's a data packet */
  
  /* If it's the last received packet --> ack might've been corrupted or lost
     --> resend ack. */
  if (ntohl(pkt->seqno) == r->last_recvd_pkt) {
    send_ack_packet(r, ntohl(pkt->seqno)+1);
    return;
  } else if (ntohl(pkt->seqno) - r->last_recvd_pkt > 1 
             || ntohl(pkt->seqno) < r->last_recvd_pkt) {
    /* Discard packets that don't have the next expected sequence number. */
    return;
  }
 
  if (!(r->waiting_to_output)) { 
    /* Only ouput if there's no previous packet waiting (i.e. conform to window=1. */
    r->waiting_to_output = true;
    memcpy(&(r->outstanding_pkt), pkt, ntohs(pkt->len));
    rel_output(r);
  }
} 

void
rel_read (rel_t *s)
{
  if (s->last_acked < s->last_seqno) {
    return;
  }
  
  char buf[MAX_DATA];
  int bytes_recvd = conn_input(s->c, buf, MAX_DATA);
  
  if (bytes_recvd == 0) { // No input to read.
    return;
  } 
  if (bytes_recvd == -1) {
    send_data_packet(s, buf, 0, s->last_seqno+1);
    s->last_seqno++;
    s->sent_eof = true;
    close_conn_if_possible(s);
    return;
  }
  send_data_packet(s, buf, bytes_recvd, s->last_seqno+1);
  s->last_seqno++;
}

void
rel_output (rel_t *r)
{
  packet_t* packet = &(r->outstanding_pkt);
  if (!(r->waiting_to_output)) { // A packet is still buffered.
    return;
  }
  if (conn_bufspace(r->c) <= ntohs(packet->len)) {
    return;
  }
  if (r->received_eof) { 
    return;
  }    
  
  /* We're good to output data: */

  int data_size = ntohs(packet->len) - MIN_DATA_PKT_LEN;
  
  if (data_size == 0) {
    r->received_eof = true;
  }
 
  conn_output(r->c, packet->data,  data_size);
  
  r->last_recvd_pkt = ntohl(packet->seqno);
  send_ack_packet(r, ntohl(packet->seqno)+1);
  r->waiting_to_output = false;
  close_conn_if_possible(r);
}

void
rel_timer ()
{
  /* Retransmit any packets that need to be retransmitted */
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int current_time = ts.tv_sec*1000; // in milliseconds/
  rel_t* r = rel_list;
  
  // Only retransmit when no ack received and we timed out.
  if (r->last_acked < r->last_seqno 
      && current_time - r->last_retransmit >= r->cc.timeout) {
    packet_t* packet = &(r->last_sent_pkt);
    send_data_packet(r, packet->data, ntohs(packet->len)-MIN_DATA_PKT_LEN, 
		     ntohl(packet->seqno));
    r->last_retransmit = current_time;
  }
  close_conn_if_possible(rel_list);
}

void
close_conn_if_possible(rel_t* r) {
  int close = true;
  if (!r->received_eof) {
    close = false;
  }
  if (!r->sent_eof) {
    close = false;
  }
  if (r->waiting_to_output) {
    close = false;
  }
  if (r->last_acked != r->last_seqno) {
    close = false;
  }
  if (close) {
    rel_destroy(r);
  }
}

void 
send_data_packet(rel_t* s, char* buf, int len, int seqno) {
  int packet_len = MIN_DATA_PKT_LEN + len;
  packet_t packet;
  uint16_t computed_cksum;
  packet.cksum = 0x0000;
  packet.ackno = 0x00000000;
  packet.seqno = htonl(seqno);
  packet.len = htons(packet_len);
  memcpy(packet.data, buf, len);
  computed_cksum  = cksum(&packet, packet_len);
  packet.cksum = computed_cksum;
  conn_sendpkt(s->c, &packet, packet_len);
  memcpy(&(s->last_sent_pkt), &packet, packet_len);
  
  // Update last retransmi
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  s->last_retransmit = ts.tv_sec * 1000; 
}


void
send_ack_packet(rel_t* r, int ackno) {
  //packet_t* packet = r->outstanding_pkt;
  packet_t ack_pkt;
  ack_pkt.cksum = 0x0000;
  ack_pkt.cksum = 0x00000000;
  ack_pkt.len = htons(ACK_PKT_LEN);
  ack_pkt.ackno = htonl(ackno);
  uint16_t computed_cksum = cksum(&ack_pkt, ACK_PKT_LEN);
  ack_pkt.cksum = computed_cksum;
  conn_sendpkt(r->c, &ack_pkt, ACK_PKT_LEN);
  //print_pkt(&ack_pkt, "ack", ntohs(ack_pkt.len));
}


int
length_verified(packet_t* packet, size_t recvd_len) {
  int advertised_len = ntohs(packet->len);
  if (recvd_len < advertised_len) {
    return false;
  }
  if (advertised_len < ACK_PKT_LEN || advertised_len > MAX_PKT_LEN) {
    return false;
  }
  if (advertised_len > ACK_PKT_LEN && advertised_len < MIN_DATA_PKT_LEN) {
    return false;
  }
  if (advertised_len != recvd_len) {
    return false;
  }
  return true;
}

int
checksum_verified(packet_t* packet, size_t recvd_len) {
  uint16_t recvd_cksum = packet->cksum;
  //printf("recvd_cksum: %04x\n", recvd_cksum);
  packet->cksum = 0x0000;
  uint16_t computed_cksum = cksum(packet, ntohs(packet->len));
  packet->cksum = recvd_cksum;
  //printf("recvd_cksum: %04x, computed_cksum: %04x\n", recvd_cksum, computed_cksum);
  return recvd_cksum == computed_cksum;
}

