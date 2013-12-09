
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

struct packets {
  struct packets* next;
  int in_use;		/* True (i.e. 1) if it's buffering a packet. */
  int last_retransmit;  /* Only used in send_pkts. */
  packet_t packet;
};

struct reliable_state {
  rel_t *next;			/* Linked list for traversing all connections */
  rel_t **prev;

  conn_t *c;			/* This is the connection object */

  /* Add your own data fields below this */
  struct config_common cc;
  struct sockaddr_storage sock;
  
  uint32_t last_acked;		/* Last acked packet (by other side). */
  uint32_t last_seqno;   	/* Last used sequence number (by me). */
  uint32_t last_recvd_pkt;	/* Last received packet seqno. */
  int pending_eof;		/* 1 if there's a partial packet in-flight, a pending 
				   partial packet, and we've received EOF from 
				   conn_input(). */
  int sent_eof;
  int received_eof;
  uint32_t partial_in_flight;   /* 0 if no partial packet in flight. Otherwise, 
                                   its value will be the seqno of partial packet. */
  int partial_pending;     	/* 0 if no partial packet is waiting for another partial
				   to be acked. 1 otherwise. */
  packet_t pending_partial_pkt; /* Used when we read a partial packet while another
				   partial is in-flight.*/
  struct packets* received_pkts;
  struct packets* sent_pkts;
};
rel_t *rel_list;

void clear_buffer_space(struct packets* pkts, int window, uint32_t seqno); 
int sockaddr_exists(const struct sockaddr_storage* ss, rel_t** match); 
int length_verified(packet_t* packet, size_t recvd_len);
int checksum_verified(packet_t* packet, size_t recvd_len);
void send_ack_packet(rel_t* r, int ackno);
void send_data_packet(rel_t* r, char* buf, int len, int seqno);
void close_conn_if_possible(rel_t* r);
void allocate_packets_buffer(struct packets** pkts, int window);
void add_to_buffer(struct packets* pkts, packet_t* pkt, int window);
void update_retransmit(struct packets* p);
void free_buffer(struct packets* p, int window);
 
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
  if (ss != NULL) {
    memcpy(&(r->sock), ss, sizeof(struct sockaddr_storage));
  }
  memcpy(&(r->cc), cc, sizeof(struct config_common));
  r->last_acked = 0x00000000;
  r->last_seqno = 0x00000000;
  r->last_recvd_pkt = 0x00000000;
  r->sent_eof = false;
  r->received_eof = false; 
  r->pending_eof = false;
  r->partial_in_flight = false;
  r->partial_pending = false;
  allocate_packets_buffer(&(r->received_pkts), cc->window);
  allocate_packets_buffer(&(r->sent_pkts), cc->window);
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
  free_buffer(r->received_pkts, r->cc.window);
  free_buffer(r->sent_pkts, r->cc.window);
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
  if (!length_verified(pkt, len)) {
    return;
  }
  if (!checksum_verified(pkt, len)) {
    return;
  }
  rel_t* r = NULL;
  if (!sockaddr_exists(ss, &r)) {
    if (ntohl(pkt->seqno) == 1) {
      r = rel_create(NULL, ss, cc);
    } else { 
      // First packet might've been dropped --> don't buffer until 
      // it's received.
      return; 
    }
  }
  // Note: If sockaddr_exists() returns true --> r will point to the 
  // matching rel_t struct.  
  rel_recvpkt(r, pkt, len);
}

void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
  /* Still need to check length and checksum in case we're not running in server
     mode (i.e. rel_demux() isn't being called. */
  if (!length_verified(pkt, n)) {
    return;
  }
  if (!checksum_verified(pkt, n)) {
    return;
  }

  if (ntohs(pkt->len) == ACK_PKT_LEN) {
    int diff = ntohl(pkt->ackno) - r->last_acked - 1; 
    if (diff >= 0 && diff <= r->cc.window) {
      r->last_acked = ntohl(pkt->ackno)-1;
      if (r->last_acked >= r->partial_in_flight) {
	r->partial_in_flight = false;
 /*       if (r->partial_pending && r->pending_eof) {
	  send_data_packet(r, r->pending_partial_pkt.data, 
			   ntohs(r->pending_partial_pkt.len)-MIN_DATA_PKT_LEN, 
			   ntohl(r->pending_partial_pkt.seqno));
	  char buf[MAX_DATA]; // Dummy buffer
	  send_data_packet(r, buf, 0, r->last_seqno++);
	  r->last_seqno++;
	  r->pending_eof = false;
	  r->sent_eof = true;
	  r->partial_pending = false;
	}*/
      } 
      clear_buffer_space(r->sent_pkts, r->cc.window, r->last_acked);
      if (r->sent_eof) { // Might be ack'ing the EOF we sent --> check if we can close.
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
  uint32_t pkt_seqno = ntohl(pkt->seqno);
  if (pkt_seqno <= r->last_recvd_pkt) {
    /* If it's the last received packet --> ack might've been corrupted or lost
       --> resend ack. */
    send_ack_packet(r, r->last_recvd_pkt+1);
    return;
  } else if (pkt_seqno > r->last_recvd_pkt 
	     && pkt_seqno <= r->last_recvd_pkt+r->cc.window) { 
    add_to_buffer(r->received_pkts, pkt, r->cc.window);
    rel_output(r);
  }
} 

void
rel_read (rel_t *s)
{
  int num_packets_to_send = s->cc.window-(s->last_seqno - s->last_acked);
  /* If we have space in window --> send packet. */
  if (s->last_seqno - s->last_acked < s->cc.window) {
    int i;
    for (i = 0; i < num_packets_to_send; i++) {
      char buf[MAX_DATA];
      int bytes_read = conn_input(s->c, buf, MAX_DATA);
      if (bytes_read == -1) {
	if (s->partial_pending) {
	  /* If partial pending --> send after pending partial is sent. */
	  s->pending_eof = true;
	  return; 
	} else {
	  /* Send EOF. It's ok if there's a partial in-flight. */
	  send_data_packet(s, buf, 0, s->last_seqno+1);
	  s->last_seqno++;
          s->sent_eof = true;
          close_conn_if_possible(s);
          return;
	}
      } else if (bytes_read > 0) {
	if (s->partial_pending) {
	  /* If partial pending --> fill partial first. */
	  packet_t* pkt = &(s->pending_partial_pkt);
	  int bytes_available = MAX_PKT_LEN - ntohs(pkt->len);
	  int writing_index = MAX_DATA - bytes_available;
          if (bytes_read < bytes_available) {
	    /* Partial won't be full --> fill bytes & return. */
	    memcpy(pkt->data+writing_index, buf, bytes_read);
	    pkt->len = htons(ntohs(pkt->len)+bytes_read);
	    return; // No need to read more since we didn't fill buf.
	  } else {
	    /* Case when partial will be full --> send full packet & create new 
	       partial if there's remaining data. */
	    memcpy(pkt->data+writing_index, buf, bytes_available);
	    pkt->len = htons(ntohs(pkt->len)+bytes_available);
	    int remaining_bytes = bytes_read - bytes_available;
	    send_data_packet(s, pkt->data, MAX_DATA, ntohl(pkt->seqno)); 
	    s->partial_pending = false;
	    if (remaining_bytes > 0) {
	      /* Create another partial for remaining data. */
	      memcpy(pkt->data, buf+bytes_available, remaining_bytes);
	      pkt->seqno = htonl(s->last_seqno+1);
	      pkt->len = htons(MIN_DATA_PKT_LEN + remaining_bytes);
	      s->partial_pending = true;
	      s->last_seqno++;
	    } 
	  }
        } else {
	  /* Case when no partial is pending. A partial could still be in-flight. */
	  packet_t pkt;
	  memcpy(pkt.data, buf, bytes_read);
	  pkt.len = htons(MIN_DATA_PKT_LEN + bytes_read);
	  pkt.seqno = htonl(s->last_seqno+1);
	  s->last_seqno++;
	  send_data_packet(s, pkt.data, bytes_read, ntohl(pkt.seqno));
	  if (bytes_read < MAX_DATA) {
  	    /* Case: Partial packet --> send packet & return. */
	    s->partial_in_flight = ntohl(pkt.seqno);
	    return; // No need to read more since we just read a partial.  
	  }
	}
      } // End of: else if (bytes_read > 0  
    } // End of: for-loop.
  } // End of: if (s->last_seqno - s->last_acked > windnow)           
}

void
rel_output (rel_t *r)
{
  if (r->received_eof) {
    return;
  }
  struct packets* p;;
  int i;
  for (i = 0; i < r->cc.window; i++) {
    p = r->received_pkts;
    int j;
    for (j = 0; j < r->cc.window; j++) {
      if (p->in_use && ntohl(p->packet.seqno) - r->last_recvd_pkt == 1) {
	packet_t* packet = &(p->packet);
	if (conn_bufspace(r->c) > ntohs(packet->len)) {
	  conn_output(r->c, packet->data, ntohs(packet->len)-MIN_DATA_PKT_LEN);
	  send_ack_packet(r, ntohl(packet->seqno)+1);
	  r->last_recvd_pkt++;
	  p->in_use = false; 
	  if (ntohs(packet->len) == MIN_DATA_PKT_LEN) {
	    /* Case: this is an EOF packet. */
	    r->received_eof = true;
	    close_conn_if_possible(r);
	  }
	  //break;
	} else { /* Case: No space in output buffer --> return. */
	  return;
	}
      }
      p = p->next;
    }
  }
}

void
rel_timer ()
{ 
  /* Retransmit any packets that need to be retransmitted */
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int current_time = ts.tv_sec*1000; // in milliseconds/
  rel_t* s = rel_list;
  
  while (s != NULL) {
    // Only retransmit when no ack received and we timed out.
    int window = s->cc.window;
    int i;
    struct packets* p = s->sent_pkts;
    for (i = 0; i < window; i++) {
      packet_t* packet = &(p->packet);
      if (p->in_use && ntohl(packet->seqno) > s->last_acked
	  && current_time - p->last_retransmit >= s->cc.timeout) {
	send_data_packet(s, packet->data, ntohs(packet->len)-MIN_DATA_PKT_LEN,
			 ntohl(packet->seqno));
      }
      p = p->next;
    }  
    s = s->next; 
  }
}

/* Sets the last retransmit time for a packet to current time. */
void
update_retransmit(struct packets* p) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  p->last_retransmit = ts.tv_sec * 1000;
}

/* First checks that the packet is not alread in the buffer. If not, it adds it. */
void
add_to_buffer(struct packets* pkts, packet_t* pkt, int window) {
  int i;
  struct packets* p = pkts;
  for (i = 0; i < window; i++) {
    if (ntohl(p->packet.seqno) == ntohl(pkt->seqno)) {
      update_retransmit(p);
      return;
    }
    p = p->next;
  }
  p = pkts;
  for (i = 0; i < window; i++) {
    if (!p->in_use) {
      memcpy(&(p->packet), pkt, MAX_PKT_LEN);
      p->in_use = true;
      update_retransmit(p);
      return;
    }
    p = p->next;
  }
}

/* Allocates memory for received_pkts & sent_pkts in rel_t. */
void
allocate_packets_buffer(struct packets** pkts, int window) {
  int i;
  *pkts = (struct packets*) malloc(sizeof(struct packets));
  (*pkts)->next = NULL;
  (*pkts)->in_use = false;
  struct packets* p = *pkts;   
  for (i = 1; i < window; i++) {
    p->next = (struct packets*) malloc(sizeof(struct packets));
    p = p->next;
    p->in_use = false;
    p->next = NULL;
  }
}

/* Free memory allocated to received_pkts & sent_pkts in rel_t. */
void
free_buffer(struct packets* p, int window) {
  int i;
  struct packets* next = p;
  for (i = 0; i < window; i++) {
    next = p->next;
    free(p);
    p = next;
  }
} 

/* Returns true if sockaddr_storage already exists in rel_list. */
int
sockaddr_exists(const struct sockaddr_storage* ss, rel_t** match) {
  rel_t* r = rel_list;
  while (r != NULL) {
    struct sockaddr_storage* r_ss = &(r->sock);
    if (addreq(r_ss, ss)) { 
      *match = r;
      return true;
    }  
    r = r->next;
  }
  return false;
}

/* Clears all packets (i.e. sets in_use to false) with sequnece number <= seqno. */
void clear_buffer_space(struct packets* pkts, int window, uint32_t seqno) {
  int i;
  for (i = 0; i < window; i++) {
    packet_t* packet = &(pkts->packet);
    if (pkts->in_use && ntohl(packet->seqno) <= seqno) {
      pkts->in_use = false;
    }
    pkts = pkts->next;
  }
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
  add_to_buffer(s->sent_pkts, &packet, s->cc.window); 
}


void
send_ack_packet(rel_t* r, int ackno) {
  packet_t ack_pkt;
  ack_pkt.cksum = 0x0000;
  ack_pkt.cksum = 0x00000000;
  ack_pkt.len = htons(ACK_PKT_LEN);
  ack_pkt.ackno = htonl(ackno);
  uint16_t computed_cksum = cksum(&ack_pkt, ACK_PKT_LEN);
  ack_pkt.cksum = computed_cksum;
  conn_sendpkt(r->c, &ack_pkt, ACK_PKT_LEN);
  print_pkt(&ack_pkt, "ack", ntohs(ack_pkt.len));
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
  packet->cksum = 0x0000;
  uint16_t computed_cksum = cksum(packet, ntohs(packet->len));
  packet->cksum = recvd_cksum;
  return recvd_cksum == computed_cksum;
}

