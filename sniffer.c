#include "sniffer.h"

//
// static global variables for managing time
//
static u_long initTimestamp = 0; // initial packet's timestamp
static u_long offsetTime = 0; // user provided time to wait till outputting packet data
static u_long startTime = 0; // time at which we can start outputting packet data
static u_long maxTime = 0; // maximum time sniffer will run for
static u_long runTime = 0; // user specified time to run for
static int userSpecifiedRuntime = 0; // bool

//
// display usage and exit
//
void usage()
{
  printf("Usage: ./sniffer [-r filename] [-i interface] [-t time] [-o time_offset]\n");
  exit(0);
}

//
// work horse that handles each packet that is read in
//
void doWork(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
  /* declare pointers to packet headers */
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const struct sniff_udp *udp;            /* The UDP header */
  const struct icmp *icmp;                /* The ICMP header */

  // Update timer
  if (initTimestamp == 0) {
    // Initialize the timer
    initTimestamp = (u_int)pkthdr->ts.tv_sec;
    if (offsetTime != 0) {
      startTime = offsetTime;
      maxTime += offsetTime + runTime;
    } else {
      startTime = initTimestamp;
      maxTime += initTimestamp + runTime;
    }
    ///*DEBUG*/fprintf(stdout, "Initialized initTimestamp =  %lu\n", initTimestamp);
    ///*DEBUG*/fprintf(stdout, "Initialized maxTime =        %lu\n", maxTime);
    ///*DEBUG*/fprintf(stdout, "Initialized startTime =      %lu\n", startTime);
  }

  // Check we're doing ok on time
  u_long currentTime = (u_long)pkthdr->ts.tv_sec;
  if (currentTime < startTime) {
    return;
  }
  if (userSpecifiedRuntime == 1 && (currentTime > maxTime)) {
    ///*DEBUG*/fprintf(stdout, "Initialized currentTime =      %lu\n", currentTime);
    fprintf(stdout, "\nRuntime limit of %lu seconds reached, exiting..\n", runTime);
    exit(0);
  }

  int size_ip;
  int size_tcp;
  
  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);
  
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  /* print timestamp */
  fprintf(stdout, "%d.%d ", (int)pkthdr->ts.tv_sec, (int)pkthdr->ts.tv_usec);
  
  /* print source and destination IP addresses */
  printf("%s -> ", inet_ntoa(ip->ip_src));
  printf("%s ", inet_ntoa(ip->ip_dst));
  
  /* determine protocol */  
  switch(ip->ip_p) {
    case IPPROTO_TCP:
      /* define/compute tcp header offset */
      tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
      }
  
      printf("TCP ");
      printf("%d->", ntohs(tcp->th_sport));
      printf("%d ", ntohs(tcp->th_dport));
      u_char flags;
      if ((flags = tcp->th_flags) & (TH_URG|TH_ACK|TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
        fprintf(stdout,"[ ");
        if (flags & TH_FIN)
          fprintf(stdout,"FIN ");
        if (flags & TH_SYN)
          fprintf(stdout,"SYN ");
        if (flags & TH_RST)
          fprintf(stdout,"RST ");
        if (flags & TH_PUSH)
          fprintf(stdout,"PSH ");
        if (flags & TH_ACK)
          fprintf(stdout,"ACK ");
        if (flags & TH_URG)
          fprintf(stdout,"URG ");
        fprintf(stdout,"] ");
      }
      printf("Seq=%u ", ntohl(tcp->th_seq));
      printf("Ack=%u ", ntohl(tcp->th_ack));
      printf("Win=%d ", ntohs(tcp->th_win));
      break;
    case IPPROTO_UDP:
      udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
      printf("UDP ");
      printf("%d->%d ", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
      break;
    case IPPROTO_ICMP:
      icmp = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);
      fprintf(stdout, "Type: %d ", icmp->icmp_type);
      fprintf(stdout, "Code: %d ", icmp->icmp_code);
      break;
    case IPPROTO_IP:
      printf("IP ");
      break;
    default:
      return;
  }
  printf("Len=%d\n", pkthdr->len);
}

int main(int argc, char* argv[])
{
  // Usage
  // %sniffer [-r filename] [-i interface] [-t time] [-o time_offset]
  if (argc == 1) {
    usage();
  }

  char *filename = NULL;
  char *interface = NULL;
  char *inputTime = NULL;
  char *time_offset = NULL;
  
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-h") == 0) {
      usage();
    } else if (strcmp(argv[i], "-r") == 0) {
      filename = argv[++i];
    } else if (strcmp(argv[i], "-i") == 0) {
      interface = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0) {
      inputTime = argv[++i];
    } else if (strcmp(argv[i], "-o") == 0) {
      time_offset = argv[++i];
    } else {
      usage();
    }
  }

  if (inputTime) {
    runTime = (int)atoi(inputTime);
    userSpecifiedRuntime = 1;
    ///*DEBUG*/  printf("runTime = %lu\n", runTime);
  }
  if (time_offset) {
    offsetTime = (int)atoi(time_offset);
    ///*DEBUG*/  printf("time_offset = %lu\n", offsetTime);
  }

  char errbuf[PCAP_ERRBUF_SIZE]; 
  char filter_exp[] = "ip";      /* filter expression [3] */
  struct bpf_program fp;         /* compiled filter program (expression) */
  bpf_u_int32 net = 0;           /* ip */



  if (filename) {
    /* open capture device */
    pcap_t *pcap = pcap_open_offline(filename, errbuf);

    /* compile the filter expression */
    if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(pcap, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }

    pcap_loop(pcap, /*all packets*/-1, doWork, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(pcap);
  } else if (interface) {
    // ignores time_offset
    pcap_t *pcap = pcap_open_live(interface, SNAP_LEN, /*promiscuous mode*/1, 1000, errbuf);

    /* compile the filter expression */
    if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(pcap, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }

    pcap_loop(pcap, /*all packets*/-1, doWork, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(pcap);
  }
    
  return 0;
}
	
