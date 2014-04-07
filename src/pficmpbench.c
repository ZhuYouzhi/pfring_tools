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
 * Date  :  2013-05-26
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
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <linux/if_ether.h>

#include "pfring.h"

/* ******************************** */
/*
 * MACROS
 */
#define ALARM_SLEEP            1
#define DEFAULT_SNAPLEN        65535
#define DEFAULT_BUF_SIZE       2048
#define MAX_NUM_THREADS        64
#define DEFAULT_DEVICE         "eth0"
#define DEFAULT_USLEEP         100
#define DEFAULT_TIME_PERIOD_US 10000
#define S_TO_US                1000000

#define SCALE_FACTOR           1.01

#define DEFAULT_IP_HDR_FLAG    5
#define DEFAULT_IP_HDR_LEN     20
#define DEFAULT_IP_ID          12345
#define DEFAULT_IP_TOT_LEN     0x1C00

#define DEFAULT_ICMP_ID        123456
#define DEFAULT_ICMP_SEQ       654321
#define DEFAULT_ICMP_CODE      0
#define DEFAULT_ICMP_TYPE      8

#define DEFAULT_PKT_LEN        42

/*
 * Global variables
 */
static pthread_t timer_thread;
static u_int64_t pkts_sent[MAX_NUM_THREADS] = {0};
static u_int64_t pkts_sent_last[MAX_NUM_THREADS] = {0};
static u_int64_t tick_timeout[MAX_NUM_THREADS] = {0};
static pfring  *ring[MAX_NUM_THREADS] = {NULL};   /* pf_ring rings */
static pthread_t pd_thread[MAX_NUM_THREADS];
static int32_t thiszone;
static u_int32_t expected_pps = 9050000;
static u_int64_t expected_pkts_num = 0;
static char str_src_ip[16] = {"192.168.1.1"};
static char str_dst_ip[16] = {"192.168.1.2"};
static u_int16_t dport = 80;
static char dst_mac[ETH_ALEN] = {0};
static char src_mac[ETH_ALEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
static int rate_control = 0;
static int fixed_src_ip = 0;
static int icmp_code = DEFAULT_ICMP_CODE;
static int icmp_type = DEFAULT_ICMP_TYPE;

/*
 * Global running parameters
 */
int verbose = 0;
int num_channels = 1;
u_int8_t wait_for_packet = 1;
u_int8_t do_shutdown = 0;
u_int8_t finish = 0;

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
  int i = 0;
  u_int64_t sent = 0;
  u_int64_t sent_last = 0;

  for(i=0; i < num_channels; i++) {
    sent += pkts_sent[i];
    sent_last += pkts_sent_last[i];
    pkts_sent_last[i] = pkts_sent[i];
  }

  printf("Total pkts: %lu pps: %lu\n", sent, sent - sent_last);
}

/*
 * General signal handler
 */
void
sigproc(int sig)
{
  static int called = 0;
  int i = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) {
    return;
  } else {
    called = 1;
  }

  do_shutdown = 1;
  print_stats();

  for(i=0; i<num_channels; i++) {
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

void
print_help(void)
{
  printf("\n\npficmpbench(C)    2013 Zhu Youzhi<zhuyouzhi@gmail.com>\n\n");
  printf("Usage: pficmpbench -i device [-r rate] [-c count]");
  printf(" [--type icmptype] [--code icmpcode]");
  printf(" --dmac nexthopmac --dip dstip [--dport dstport] [--sip srcip]\n\n");
  printf("-i <device>        Device name [Man]\n");
  printf("-r <rate>          Packet send rate in pps, at fastest speed if not specified [Opt, fastest rate as default]\n");
  printf("-c <count>         Send how many packets, 0 stands for ever [Opt, 0 as default}\n");
  /*printf("--code <icmpcode>  Icmp code [Opt, 0 as default]\n");*/
  printf("--type <icmptype>  Icmp type [Opt, 8 as default]\n");
  printf("--dmac <dstmac>    Specify next hop mac [Man]\n");
  printf("--dip <dstip>      Specify destination ip address [Man]\n");
  printf("--dport <dstport>  Specify destination port number [Opt, 80 as default]\n");
  printf("--sip <srcip>      Specify fixed src ip address [Opt]\n");
  printf("-h                 Print help info\n");
}

int32_t
gmt2local(time_t t)
{
  int dt = 0;
  int dir = 0;
  struct tm *gmt = NULL;
  struct tm *loc = NULL;
  struct tm sgmt;

  if(t == 0){
    t = time(NULL);
  }
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
  if(dir == 0){
    dir = loc->tm_yday - gmt->tm_yday;
  }
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/*
 * Checksum implementation
 */
inline unsigned short
csum(unsigned short *p,int n) {
  register long sum = 0;
  register short chksum = 0;
  unsigned short odd = 0;

  while(n > 1) {
    sum += *p++;
    n -= 2;
  }

  if(n == 1) {
    *((u_char*)&odd) = *(u_char*)p;
    sum += odd;
  }

  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  chksum =(short)~sum;

  return chksum;
}

/*
 * Provide ms precision timer service
 */
void*
timer_thread_func(void* _id)
{
  int i = 0;
  struct timeval time1;
  time1.tv_sec = 0;
  time1.tv_usec = DEFAULT_TIME_PERIOD_US;
  while(1)
  {
    if (do_shutdown == 1 || finish == 1){
      break;
    }
    switch(select(0,NULL,NULL,NULL,&time1)){
    case 0 :
      time1.tv_sec = 0;
      time1.tv_usec = DEFAULT_TIME_PERIOD_US;
      for(i=0; i<num_channels; i++) {
        tick_timeout[i] = 1;
      }
      break;
    default :
      break;
    }
  }

  return NULL;
}

/*
 * Thread to send packet
 */
void*
packet_sender_thread(void* id)
{
  int s;
  long thread_id = (long)id;
  pfring  *pd = ring[thread_id];
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  u_long core_id = thread_id % numCPU;

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

  char buffer[DEFAULT_BUF_SIZE] = {0};

  /*
   * Set dst mac and ethernet frame type
   */
  memcpy(buffer, dst_mac, ETH_ALEN);
  memcpy(buffer+ETH_ALEN, src_mac, ETH_ALEN);
  buffer[ETH_ALEN + ETH_ALEN] = ETH_P_IP >> 8 & 0xFF;
  buffer[ETH_ALEN + ETH_ALEN + 1] = ETH_P_IP & 0xFF;

  /*
   * Fill ip packet members
   */
  struct iphdr *iph = (struct iphdr *)(buffer + ETH_HLEN);
  iph->ihl = DEFAULT_IP_HDR_FLAG;
  iph->version = IPVERSION;
  iph->tot_len = DEFAULT_IP_TOT_LEN;
  iph->id = htons(DEFAULT_IP_ID);
  iph->ttl = IPDEFTTL;
  iph->protocol = IPPROTO_ICMP;
  iph->daddr = inet_addr(str_dst_ip);

  struct icmphdr *icmph = (struct icmphdr *) (buffer + sizeof (struct ip) + ETH_HLEN);
  icmph->code = icmp_code;
  icmph->type = icmp_type;
  icmph->un.echo.id = (u_int16_t)DEFAULT_ICMP_ID;
  icmph->un.echo.sequence = (u_int16_t)DEFAULT_ICMP_SEQ;

  /*
   * Src ip is generated randomly on each tick timeout,
   * and increase linearly in timeout
   */
  srand((unsigned) time(NULL));
  u_int32_t rand_val = rand();

  u_int32_t sip = 0;
  if (fixed_src_ip == 1) {
    sip = inet_addr(str_src_ip);
  }
  int icmp_hdr_len = sizeof(struct icmphdr);

  while(1){

    if (do_shutdown == 1){
      return NULL;
    }

    if (tick_timeout[thread_id] == 1){
      tick_timeout[thread_id] = 0;
      rand_val = rand();
      rand_val *= rand_val;
    }

    if (rate_control == 1){

      int i = 0;
      for(i = 0; i < expected_pps; i++){

        if(expected_pkts_num && (pkts_sent[thread_id] >= expected_pkts_num)){
          return NULL;
        }

        if (fixed_src_ip == 0){
          sip = htonl(rand_val++);
        }

        iph->saddr = sip;
        iph->check = 0;
        iph->check = csum((unsigned short *)(iph), DEFAULT_IP_HDR_LEN);

        icmph->checksum = csum((unsigned short*)(icmph), icmp_hdr_len);

        pfring_send(pd, buffer, DEFAULT_PKT_LEN, 0 );
        pkts_sent[thread_id]++;

      }

      /*
       * Wait for next tick timeout
       */
      while(tick_timeout[thread_id] == 0){
        usleep(DEFAULT_USLEEP);
      }

    }else{

      if(expected_pkts_num && (pkts_sent[thread_id] >= expected_pkts_num)){
        return NULL;
      }

      if (fixed_src_ip == 0) {
        sip = htonl(rand_val++);
      }

      iph->saddr = sip;
      iph->check = 0;
      iph->check = csum((unsigned short *)(iph), DEFAULT_IP_HDR_LEN);

      icmph->checksum = csum((unsigned short*)(icmph), icmp_hdr_len);

      pfring_send(pd, buffer, DEFAULT_PKT_LEN, 0 );
      pkts_sent[thread_id]++;

    }
  }

  return NULL;
}

/*
 * Entry point
 */
int
main(int argc, char* argv[])
{
  char *device = NULL;
  int snaplen = DEFAULT_SNAPLEN;
  int rc = 0;
  int watermark = 0;
  int rehash_rss = 1;
  packet_direction direction = rx_and_tx_direction;
  long i = 0;
  u_int16_t cpu_percentage = 0;
  u_int16_t poll_duration = 0;
  u_int32_t version = 0;;

  thiszone = gmt2local(0);

  int opt = 0;
  char **argvopt = NULL;
  int option_index = 0;
  //char tcpflags[8] = {0};
  static struct option lgopts[] = {
    {"dip", 1, 0, 0},
    {"dmac", 1, 0, 0},
    {"dport", 1, 0, 0},
    {"sip", 1, 0, 0},
    {"code", 1, 0, 0},
    {"type", 1, 0, 0},
    {NULL, 0, 0, 0}
  };

  argvopt = argv;

  while ((opt = getopt_long(argc, argvopt, "hi:r:c:",
        lgopts, &option_index)) != EOF) {

    switch(opt){
    case 'h':
      print_help();
      return(0);
    case 'i':
      device = strdup(optarg);
      break;
    case 'r':
      rate_control = 1;
      expected_pps = atoi(optarg);
      break;
    case 'c':
      expected_pkts_num = atoi(optarg);
      break;
    case 0:
      if(!strcmp(lgopts[option_index].name, "dip")) {
        strcpy(str_dst_ip, optarg);
      }
      if(!strcmp(lgopts[option_index].name, "dport")) {
        dport = atoi(optarg);
      }
      if(!strcmp(lgopts[option_index].name, "dmac")) {
        u_int mac_a = 0;
        u_int mac_b = 0;
        u_int mac_c = 0;
        u_int mac_d = 0;
        u_int mac_e = 0;
        u_int mac_f = 0;
        if(sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X",
                   &mac_a,
                   &mac_b,
                   &mac_c,
                   &mac_d,
                   &mac_e,
                   &mac_f) != 6) {
          printf("Invalid mac address: %s\n", lgopts[option_index].name);
        }else{
          dst_mac[0] = mac_a;
          dst_mac[1] = mac_b;
          dst_mac[2] = mac_c;
          dst_mac[3] = mac_d;
          dst_mac[4] = mac_e;
          dst_mac[5] = mac_f;
        }
      }
      if(!strcmp(lgopts[option_index].name, "sip")) {
        fixed_src_ip = 1;
        strcpy(str_src_ip, optarg);
      }
      if(!strcmp(lgopts[option_index].name, "code")) {
        icmp_code = atoi(optarg);
      }
      if(!strcmp(lgopts[option_index].name, "type")) {
        icmp_type = atoi(optarg);
      }
      break;
    default:
      return -1;

    }

  }

  if(verbose) {
    watermark = 1;
  }
  if(device == NULL) {
    device = DEFAULT_DEVICE;
  }

  printf("Capturing from %s\n", device);

  /* hardcode: promisc=1, to_ms=500 */
  num_channels = pfring_open_multichannel(device, snaplen,
                    PF_RING_PROMISC, ring);

  if(num_channels <= 0) {
    fprintf(stderr, "pfring_open_multichannel() returned %d [%s]\n",
              num_channels, strerror(errno));
    return(-1);
  }

  if (num_channels > MAX_NUM_THREADS) {
    printf("Too many channels (%d), using %d channels\n",
       num_channels, MAX_NUM_THREADS);
    num_channels = MAX_NUM_THREADS;
  } else {
    printf("Found %d channels\n", num_channels);
  }
  pfring_version(ring[0], &version);

  printf("Using PF_RING v.%d.%d.%d\n",
   (version & 0xFFFF0000) >> 16,
   (version & 0x0000FF00) >> 8,
   version & 0x000000FF);

  expected_pps = (expected_pps*SCALE_FACTOR) / num_channels;
  expected_pps /= (S_TO_US/DEFAULT_TIME_PERIOD_US);
  expected_pkts_num /= num_channels;

  for(i=0; i<num_channels; i++) {
    char buf[DEFAULT_BUF_SIZE];

    snprintf(buf, sizeof(buf), "pficmpbench-thread %ld", i);
    pfring_set_application_name(ring[i], buf);

    if((rc = pfring_set_direction(ring[i], direction)) != 0) {
      fprintf(stderr,
       "pfring_set_direction returned %d [direction=%d]\n",
        rc, direction);
    }

    if((rc = pfring_set_socket_mode(ring[i], send_and_recv_mode)) != 0) {
      fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);
    }

    if(watermark > 0) {
      if((rc = pfring_set_poll_watermark(ring[i], watermark)) != 0) {
        fprintf(stderr,
           "pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n",
            rc, watermark);
      }
    }

    if(rehash_rss) {
      pfring_enable_rss_rehash(ring[i]);
    }

    if(poll_duration > 0) {
      pfring_set_poll_duration(ring[i], poll_duration);
    }

    pfring_enable_ring(ring[i]);

    pthread_create(&pd_thread[i], NULL, packet_sender_thread, (void*)i);
  }

  if(cpu_percentage > 0) {
    if(cpu_percentage > 99) {
      cpu_percentage = 99;
    }
    pfring_config(cpu_percentage);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pthread_create(&timer_thread, NULL, timer_thread_func, NULL);

  for(i=0; i<num_channels; i++){
    pthread_join(pd_thread[i], NULL);
    pfring_close(ring[i]);
  }

  finish = 1;
  pthread_join(timer_thread, NULL);

  print_stats();

  return(0);

}
