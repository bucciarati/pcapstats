typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;

#define _POSIX_SOURCE  /* needed for sigaction */

#include <pcap/pcap.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <net/if.h>

#define STATIC static

STATIC
void callback (u_char *, const struct pcap_pkthdr *, const u_char *);

STATIC
void alrm_handler (int signum);

int fmt_unix = 0;

int main ( int argc, char ** argv ){
  char interface[IF_NAMESIZE + 1] = "eth0";
  char *pcap_filter = NULL;

  static struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"unix-timestamp", no_argument, 0, 'u'},
    {0, 0, 0, 0},
  };

  unsigned need_help = 0;
  int c;
  while ( ( c = getopt_long(argc, argv, "i:u", long_options, NULL) ) != -1 ){
    switch (c) {

      case 'i':
        strncpy(interface, optarg, IF_NAMESIZE);
        fprintf(stderr, "# setting interface to \"%s\"\n", interface);
        break;

      case 'u':
        fmt_unix = 1;
        fprintf(stderr, "# output format: UNIX timestamp\n");
        break;

      case '?':
      default:
        need_help = 1;
        break;
    }
  }

  /* we want exactly one argument after the options */
  if ( optind == argc - 1 ){
    pcap_filter = argv[optind];
    fprintf(stderr, "# pcap_filter: [%s]\n", pcap_filter);
  }

  need_help = need_help || !pcap_filter;
  if ( need_help ){
    fprintf(stderr, "usage example: %s [--interface|-i $iface] [--unix-timestamp|-u] 'port 11211'\n", argv[0]);
    fprintf(stderr, "see man 7 pcap-filter for the argument format\n");
    fprintf(stderr, "e.g. new incoming SSH connections per second: 'dst port 22 and tcp[13] == 2'\n");
    exit(1);
  }

  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *capture = pcap_open_live(
      interface,
      420,        /* snaplen */
      1,          /* promisc */
      1000,       /* to_ms (timeout) */
      errbuf
  );

  if ( capture == NULL ){
    fprintf(stderr, "can't pcap_open_live(): [%s]\n", errbuf);
    exit(1);
  }

  struct bpf_program fp;
  bpf_u_int32 netmask = 0;

  int compiled = pcap_compile(
      capture,
      &fp,
      pcap_filter,
      1,
      netmask
  );

  if ( compiled != 0 ){
    fprintf(stderr, "can't pcap_compile(): [%s]\n", pcap_geterr(capture));
    exit(1);
  }

  int filtering = pcap_setfilter(
      capture,
      &fp
  );

  if ( filtering != 0 ){
    fprintf(stderr, "can't pcap_setfilter(): [%s]\n", pcap_geterr(capture));
    exit(1);
  }

  struct sigaction alrm_action;
  alrm_action.sa_handler = alrm_handler;
  sigemptyset(&alrm_action.sa_mask);
  alrm_action.sa_flags = 0;

  sigaction(SIGALRM, &alrm_action, NULL);
  alarm(1);

  int retval = -1;
  while ( ( retval = pcap_loop( capture, 1, callback, NULL ) ) >= 0 ){
    /* fprintf(stdout, "pcap_loop() returned %d\n", retval); */
  }

  return 0;
}

static unsigned long count_times = 0;
static unsigned long count_bits = 0;

STATIC
void callback (u_char *user __attribute__((unused)), const struct pcap_pkthdr *h __attribute__((unused)), const u_char *bytes __attribute((unused))){
  count_times++;
  count_bits += 8 * h->len;
  /* fprintf(stdout, "I am called %lu (%p, %p, %p)\n", count_times, user, h, bytes); */
}

STATIC
void alrm_handler (int signum){
  struct timeval tv;
  struct tm *current_time;

  /* fprintf(stdout, "I got signal %d, count_times is %lu\n", signum, count_times); */

  /* this callback should only handle SIGALRM */
  if ( signum != SIGALRM )
    return;

  gettimeofday(&tv, NULL);

  if ( fmt_unix ){
    fprintf(stdout, "%u %lu %lu\n",
        (unsigned)tv.tv_sec,
        count_times,
        count_bits
    );
  } else {
    current_time = localtime(&tv.tv_sec);
    fprintf(stdout, "%02d:%02d:%02d %lu %lu\n",
        current_time->tm_hour,
        current_time->tm_min,
        current_time->tm_sec,
        count_times,
        count_bits
    );
  }

  /* reset so we get the delta per second */
  count_times = 0;
  count_bits = 0;

  alarm(1);
}

/* vim: tabstop=2 shiftwidth=2 expandtab cindent:
*/
