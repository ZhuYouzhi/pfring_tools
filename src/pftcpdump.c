/*
 *
 * (C) 2005-13 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Author:  Zhu Youzhi<zhuyouzhi@gmail.com>
 * Date  :  2013-05-12
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"

/* ******************************** */
/*
 * MACROS definitions
 */
#define ALARM_SLEEP             1
#define DEFAULT_SNAPLEN     65535
#define MAX_NUM_THREADS        64
#define DEFAULT_DEVICE     "eth0"


/* ******************************** */
/*
 * Structs definitions
 */
typedef struct dump_stats_struct
{
  pfring_stat pfringStats;
  u_int64_t lastDropped;
  u_int64_t lastRecved;
} dump_stats_t; /* stats info for dumping */


/*
 * Global variables
 */
char dumpfilename[128] = {0};              /* pcap file name */
dump_stats_t dump_stats[MAX_NUM_THREADS];  /* per-thread stats info */
int thread_fd[MAX_NUM_THREADS];            /* per-thread pcap file fd*/
int dump_rotate_flag[MAX_NUM_THREADS];     /* per-thread rotate flag */
pthread_t pd_thread[MAX_NUM_THREADS];      /* per-thread thread handle */
pfring  *ring[MAX_NUM_THREADS] = {NULL};   /* pf_ring rings */
static int32_t thiszone;

/*
 * global running parameters
 */
int verbose = 0;
int num_channels = 1;
u_int8_t wait_for_packet = 1;
u_int8_t do_shutdown = 0;

/* ******************************** */
/*
 * Functions
 */

/*
 * Output statistics info
 */
void
print_stats()
{
  int i;
  u_int64_t recv = 0;
  u_int64_t drop = 0;
  u_int64_t recv_cycle = 0;
  u_int64_t drop_cycle = 0;

  for(i=0; i < num_channels; i++) {

    pfring_stats(ring[i], &(dump_stats[i].pfringStats));

    recv += dump_stats[i].pfringStats.recv;
    drop += dump_stats[i].pfringStats.drop;

    recv_cycle += dump_stats[i].pfringStats.recv - dump_stats[i].lastRecved;
    drop_cycle += dump_stats[i].pfringStats.drop - dump_stats[i].lastDropped;

    dump_stats[i].lastRecved = dump_stats[i].pfringStats.recv;
    dump_stats[i].lastDropped = dump_stats[i].pfringStats.drop;

  }

  /*printf("recved: %lu droped: %lu, recv pps: %lu, drop pps: %lu\n",
          recv, drop, recv_cycle, drop_cycle);*/

  printf("recved: %lu droped: %lu\n", recv, drop);
}

/*
 * Set rotate flags upon SIGUSR1
 */
void
usr1sig_handler(int sig)
{
  int i = 0;
  for (i = 0; i < MAX_NUM_THREADS; i++){
    dump_rotate_flag[i] = 1;
  }
}

/*
 * General signal handler
 */
void
sigproc(int sig)
{
  static int called = 0;
  int i;

  fprintf(stderr, "Leaving...\n");
  if (called){
    return;
  } else {
    called = 1;
  }

  do_shutdown = 1;
  print_stats();

  for (i=0; i<num_channels; i++) {
    pfring_shutdown(ring[i]);
  }

  return;
}

/*
 * Timeout handler
 */
void
my_sigalarm(int sig)
{
  if (do_shutdown){
    return;
  }
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

void printHelp(void) {
  printf("pftcpdump\n(C) 2013 Zhu Youzhi<zhuyouzhi@gmail.com>\n\n");
  printf("-i <device>     Device name\n");
  printf("-s <len>        Capture length\n");
  printf("-w <outputfile> Output file name\n");
  printf("-h              Print help info\n");
}

/*
 * Parse and store packets
 */
void
packet_handler(struct pfring_pkthdr *h,
       const u_char *p, const u_char *user_bytes,
       int fd)
{
  struct ether_header ehdr;
  u_short eth_type, vlan_id;
  char buf[2048] = {0};
  int s;
  uint nsec;

  if(h->ts.tv_sec == 0){
    gettimeofday((struct timeval*)&h->ts, NULL);
  }

  s = (h->ts.tv_sec + thiszone) % 86400;
  nsec = h->extended_hdr.timestamp_ns % 1000;

  memcpy(&ehdr, p+h->extended_hdr.parsed_header_len,
         sizeof(struct ether_header));
  eth_type = ntohs(ehdr.ether_type);

  if(eth_type == 0x8100) {
    vlan_id = (p[14] & 15)*256 + p[15];
    eth_type = (p[16])*256 + p[17];
    p+=4;
  }

  if(eth_type == 0x0800) {
    u_int caplen = h->caplen;
    u_int length = h->len;
    struct ether_header *eth_header = (struct ether_header *) p;

    if (length < sizeof(struct ether_header)) {
      printf("warning: received incomplete ethernet frame\n");
      return;
    }

    /* we're only expecting IP datagrams, nothing else */
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
      printf("warning: received ethernet frame with unknown type %x\n",
            ntohs(eth_header->ether_type));
      return;
    }

    if (h->caplen > DEFAULT_SNAPLEN){
      struct ether_header *eth_header = (struct ether_header *) p;
      if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf ("warning: received ethernet frame with unknown type %x",
        ntohs(eth_header->ether_type));
        return;
      }

      printf("caplen is too long, %u, %u, %x\n", h->caplen, h->len,
              ntohs(eth_header->ether_type));
      return;
    }

    unsigned int tv_sec = h->ts.tv_sec;
    unsigned int tv_usec = h->ts.tv_usec;

    /*
     * form packet head
     */
    memcpy(buf, &tv_sec, 4);
    memcpy(buf+4, &tv_usec, 4);
    memcpy(buf+8, &caplen, 4);
    memcpy(buf+12, &length, 4);

    /*
     * copy packet body
     */
    memcpy(buf+16, p, caplen);

    write(fd, buf, 16+caplen);
  }
}

int32_t
gmt2local(time_t t)
{
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/*
 * Do the rotate job
 */
void
rotate_dump_file(long thread_id)
{
  if (thread_fd[thread_id] != -1){
    close(thread_fd[thread_id]);
    thread_fd[thread_id] = open(dumpfilename,
             O_WRONLY | O_CREAT | O_APPEND, 644);
  }
}

/*
 * Thread to handle comming packets
 */
void*
packet_consumer_thread(void* _id)
{
  int s;
  long thread_id = (long)_id;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  u_long core_id = thread_id % numCPU;

  thread_fd[thread_id] = open(dumpfilename,
        O_WRONLY | O_CREAT | O_APPEND, 644);

  if(numCPU > 1) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if((s = pthread_setaffinity_np(pthread_self(),
          sizeof(cpu_set_t), &cpuset)) != 0){
      fprintf(stderr, "Error while binding thread %ld to core %ld: errno=%i\n",
       thread_id, core_id, s);
    } else {
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
    }
  }

  while(1) {

    u_char *buffer = NULL;
    struct pfring_pkthdr hdr;

    if(do_shutdown){
      break;
    }

    if(pfring_recv(ring[thread_id], &buffer, 0, &hdr, wait_for_packet) > 0) {
      if(do_shutdown){
        break;
      }
      packet_handler(&hdr, buffer, (u_char*)thread_id, thread_fd[thread_id]);
    } else {
      if(wait_for_packet == 0) {
        sched_yield();
      }
    }

    if(dump_rotate_flag[thread_id] == 1){
      rotate_dump_file(thread_id);
      dump_rotate_flag[thread_id] = 0;
    }
  }

  close(thread_fd[thread_id]);

  return(NULL);
}

/*
 * Entry point
 */
int
main(int argc, char* argv[])
{

  char *device = NULL;
  char c;
  char *output_file = NULL;
  int snaplen = DEFAULT_SNAPLEN;
  int rc =0;
  int watermark = 0;
  int rehash_rss = 1;
  packet_direction direction = rx_and_tx_direction;
  long i;
  u_int16_t cpu_percentage = 0, poll_duration = 0;
  u_int32_t version;

  thiszone = gmt2local(0);

  while((c = getopt(argc,argv,"hi:s:w:" /* "f:" */)) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 's':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'w':
      output_file = strdup(optarg);
      break;
    }
  }

  if(verbose) watermark = 1;
  if(device == NULL) device = DEFAULT_DEVICE;

  printf("Capturing from %s\n", device);

  /* hardcode: promisc=1, to_ms=500 */
  num_channels = pfring_open_multichannel(device, snaplen,
                    PF_RING_PROMISC, ring);

  if(num_channels <= 0) {
    fprintf(stderr, "pfring_open_multichannel() returned %d [%s]\n",
              num_channels, strerror(errno));
    return(-1);
  }

  for(i = 0; i < MAX_NUM_THREADS; i++){
    memset(&(dump_stats[i]), 0, sizeof(dump_stats_t));
    thread_fd[i] = -1;
    dump_rotate_flag[i] = 0;
  }

  if (num_channels > MAX_NUM_THREADS) {
    printf("Too many channels (%d), using %d channels\n",
       num_channels, MAX_NUM_THREADS);
    num_channels = MAX_NUM_THREADS;
  } else {
    printf("Found %d channels\n", num_channels);
  }

  char pcap_header[24] = {0xd4, 0xc3, 0xb2, 0xa1,
                          0x02, 0x00, 0x04, 0x00,
                          0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00};
  char pcap_linktype[4] = {0x01, 0x00, 0x00, 0x00};

  /* forge filename with timestamp */
  /*struct tm *local;
  time_t t;
  time(&t);
  local = localtime(&t);
  sprintf(dumpfilename, "pf_ring-%04d-%02d-%02d-%02d-%02d-%02d.pcap", 1900+local->tm_year, 1+local->tm_mon, local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);*/

  if (output_file == NULL){
    sprintf(dumpfilename, "%s", "dump.pcap");
  } else {
    sprintf(dumpfilename, "%s", output_file);
  }

  int fd = open(dumpfilename, O_WRONLY | O_TRUNC | O_CREAT, 644);
  write(fd, pcap_header, 16);
  write(fd, (char *)&snaplen, 4);
  write(fd, pcap_linktype, 4);
  close(fd);

  pfring_version(ring[0], &version);
  printf("Using PF_RING v.%d.%d.%d\n",
   (version & 0xFFFF0000) >> 16,
   (version & 0x0000FF00) >> 8,
   version & 0x000000FF);

  for(i=0; i<num_channels; i++) {
    char buf[32];

    snprintf(buf, sizeof(buf), "dump_packet-thread %ld", i);
    pfring_set_application_name(ring[i], buf);

    if((rc = pfring_set_direction(ring[i], direction)) != 0) {
      fprintf(stderr,
       "pfring_set_direction returned %d [direction=%d]\n",
        rc, direction);
    }

    if((rc = pfring_set_socket_mode(ring[i], recv_only_mode)) != 0) {
      fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);
    }

    if(watermark > 0) {
      if((rc = pfring_set_poll_watermark(ring[i], watermark)) != 0) {
        fprintf(stderr,
           "pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n",
            rc, watermark);
      }
    }

    if(rehash_rss)
      pfring_enable_rss_rehash(ring[i]);

    if(poll_duration > 0)
      pfring_set_poll_duration(ring[i], poll_duration);

    pfring_enable_ring(ring[i]);

    pthread_create(&pd_thread[i], NULL, packet_consumer_thread, (void*)i);
  }

  if(cpu_percentage > 0) {
    if(cpu_percentage > 99) cpu_percentage = 99;
    pfring_config(cpu_percentage);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGUSR1, usr1sig_handler);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  for(i=0; i<num_channels; i++){
    pthread_join(pd_thread[i], NULL);
    pfring_close(ring[i]);
  }

  return(0);

}
