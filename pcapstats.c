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

#define STATIC static

STATIC
void callback (u_char *, const struct pcap_pkthdr *, const u_char *);

STATIC
void alrm_handler (int signum);

int main ( int argc, char ** argv ){
  if ( argc != 3 ){
    fprintf(stderr, "usage example: %s 'port 11211'\n", argv[0]);
    exit(1);
  }

  char *interface = argv[1];
  char *rule = argv[2];

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
      rule,
      1,
      netmask
  );

  if ( compiled != 0 ){
    fprintf(stderr, "can't pcap_open_live(): [%s]\n", errbuf);
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

STATIC
void callback (u_char *user __attribute__((unused)), const struct pcap_pkthdr *h __attribute__((unused)), const u_char *bytes __attribute((unused))){
  count_times++;
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
  current_time = localtime(&tv.tv_sec);

  fprintf(stdout, "%02d:%02d:%02d %lu\n",
      current_time->tm_hour,
      current_time->tm_min,
      current_time->tm_sec,
      count_times);

  /* reset so we get the delta per second */
  count_times = 0;

  alarm(1);
}
