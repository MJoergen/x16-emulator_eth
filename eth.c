#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static char eth_filename[256];
static FILE *eth_file;

static uint16_t eth_rx;
static uint8_t eth_rx_mem[0x800];
static uint8_t eth_rx_own;

static uint16_t eth_tx;
static uint8_t eth_tx_mem[0x800];
static uint8_t eth_tx_own;

static uint16_t eth_tx_counter;

static uint16_t eth_rx_counter;

static uint8_t eth_buffer[0x800];
static bool eth_buffer_valid = false;

typedef struct __attribute__((__packed__)) {
   uint16_t length;
} t_eth_header;

typedef struct __attribute__((__packed__)) {
   t_eth_header eth_header;
   uint8_t      dst[6];
   uint8_t      src[6];
   uint16_t     typelen;
} t_mac_header;

typedef struct __attribute__((__packed__)) {
   t_mac_header mac_header;
   uint8_t      version;
   uint8_t      tos;
   uint16_t     len;
   uint16_t     id;
   uint16_t     frags;
   uint8_t      ttl;
   uint8_t      prot;
   uint16_t     chksum;
   uint32_t     src;
   uint32_t     dst;
} t_ip_header;

typedef struct __attribute__((__packed__)) {
   t_mac_header mac_header;
   uint16_t     htype;
   uint16_t     ptype;
   uint8_t      hlen;
   uint8_t      plen;
   uint16_t     oper;
   uint8_t      sha[6];
   uint32_t     spa;
   uint8_t      tha[6];
   uint32_t     tpa;
} t_arp_header;

typedef struct __attribute__((__packed__)) {
   t_ip_header ip_header;
   uint16_t    src;
   uint16_t    dst;
   uint16_t    len;
   uint16_t    chksum;
} t_udp_header;

typedef struct __attribute__((__packed__)) {
   t_udp_header udp_header;
   uint16_t     opcode;
   uint16_t     block;
   uint8_t      data[512];
} t_tftp_header;

static inline uint16_t ntohs(uint16_t v)
{
   return ((v & 0x00ff) << 8) |
          ((v & 0xff00) >> 8);
} // ntohs

#define htons ntohs

static inline uint32_t ntohl(uint32_t v)
{
   return ((v & 0x000000ff) << 24) |
          ((v & 0x0000ff00) << 8)  |
          ((v & 0x00ff0000) >> 8)  |
          ((v & 0xff000000) >> 24);
} // ntohl

#define htonl ntohl

static void
eth_arp_respond()
{
   t_arp_header *arp_rx_header = (t_arp_header *) eth_tx_mem;

   if (ntohs(arp_rx_header->oper) == 0x0001)
   {
      // ARP request

      // Use received packet as template
      memcpy(eth_buffer, eth_tx_mem, 0x800);

      t_arp_header *arp_tx_header = (t_arp_header *) eth_buffer;

      arp_tx_header->oper = htons(0x0002);      // ARP reply
      memcpy(arp_tx_header->tha, arp_rx_header->sha, 10); // Originators MAC and IP

      arp_tx_header->spa = arp_rx_header->tpa;              // Servers IP address
      arp_tx_header->sha[0] = 0x00;                         // Servers MAC address
      arp_tx_header->sha[1] = 0x11;
      arp_tx_header->sha[2] = 0x22;
      arp_tx_header->sha[3] = 0x33;
      arp_tx_header->sha[4] = 0x44;
      arp_tx_header->sha[5] = 0x55;

      eth_buffer_valid = true;
      eth_rx_counter = 200;   // Corresponds to 276 bytes of the MAC frame.
   }
} // eth_arp_respond

static void
eth_tftp_respond()
{
   int bytes_read;
   int udp_payload_len;
   uint16_t block;
   uint32_t address;

   // TFTP packet
   t_tftp_header *tftp_rx_header = (t_tftp_header *) eth_tx_mem;

   // Use received packet as template
   memcpy(eth_buffer, eth_tx_mem, 0x800);
   t_tftp_header *tftp_tx_header = (t_tftp_header *) eth_buffer;

   udp_payload_len = 0;
   switch (ntohs(tftp_rx_header->opcode))
   {
      case 0x0001 : // RRQ
         // Copy filename
         strncpy(eth_filename, (char *)(&tftp_rx_header->block), sizeof(eth_filename));

         // Try to open file for read
         eth_file = fopen(eth_filename, "rb");
         if (!eth_file) {
            printf("Cannot open %s!\n", eth_filename);
            return;
         }

         // Build TFTP response
         tftp_tx_header->opcode = htons(0x0003);             // DATA
         tftp_tx_header->block  = htons(0x0001);             // First block
         bytes_read = fread(tftp_tx_header->data, 1, 512, eth_file);

         printf("read_block: 0x00000000: ");
         for (int i=0; i<0x200 && i<bytes_read; ++i)
         {
            printf("%02x ", tftp_tx_header->data[i]);
            if ((i&15)==15)
            {
               printf("\n");
               printf("                        ");
            }
         }
         printf("\n");

         udp_payload_len = bytes_read+4;
         break;

      case 0x0002 : // WRQ
         // Copy filename
         strncpy(eth_filename, (char *)(&tftp_rx_header->block), sizeof(eth_filename));

         // Try to open file for write
         eth_file = fopen(eth_filename, "wb");
         if (!eth_file) {
            printf("Cannot open %s!\n", eth_filename);
            return;
         }

         // Build TFTP response
         tftp_tx_header->opcode = htons(0x0004);             // ACK
         tftp_tx_header->block  = htons(0x0000);             // No blocks received yet

         udp_payload_len = 4;
         break;

      case 0x0003 : // DATA
         block      = ntohs(tftp_rx_header->block);
         address    = (block-1)*512UL;
         bytes_read = ntohs(tftp_tx_header->udp_header.len)-8-4;

         printf("address:%08x, bytes:%04x\n", address, bytes_read);
         fseek(eth_file, address, SEEK_SET);
         fwrite(tftp_rx_header->data, 1, bytes_read, eth_file);
         if (bytes_read < 512)
         {
            fclose(eth_file);
         }

         // Build TFTP response
         tftp_tx_header->opcode = htons(0x0004);             // ACK
         tftp_tx_header->block  = htons(block);

         udp_payload_len = 4;
         break;

      case 0x0004 : // ACK
         block = ntohs(tftp_rx_header->block);
         address = block*512UL;

         // Build TFTP response
         tftp_tx_header->opcode = htons(0x0003);             // DATA
         tftp_tx_header->block  = htons(block+1);            // Next block
         fseek(eth_file, address, SEEK_SET);
         bytes_read = fread(tftp_tx_header->data, 1, 512, eth_file);

         printf("read_block: 0x%08x: ", address);
         for (int i=0; i<0x200 && i<bytes_read; ++i)
         {
            printf("%02x ", tftp_tx_header->data[i]);
            if ((i&15)==15)
            {
               printf("\n");
               printf("                        ");
            }
         }
         printf("\n");

         udp_payload_len = bytes_read+4;
         break;

      case 0x0005 : // ERROR
         break;

      default:
         break;
   }

   if (udp_payload_len)
   {
      // UDP header
      tftp_tx_header->udp_header.dst = tftp_rx_header->udp_header.src;
      tftp_tx_header->udp_header.src = htons(0x4A4D);    // "JM"
      tftp_tx_header->udp_header.len = htons(udp_payload_len+8);

      // IP header
      tftp_tx_header->udp_header.ip_header.dst = tftp_rx_header->udp_header.ip_header.src;
      tftp_tx_header->udp_header.ip_header.src = tftp_rx_header->udp_header.ip_header.dst;

      // length is in little-endian
      tftp_tx_header->udp_header.ip_header.mac_header.eth_header.length =
         udp_payload_len + 8 + 20 + 14;

      eth_buffer_valid = true;
      eth_rx_counter   = 200 + udp_payload_len;
   }

} // eth_tftp_respond


// Respond to ethernet frame sent by ROM.
static void
eth_respond()
{
   t_mac_header *mac_header = (t_mac_header *) eth_tx_mem;

   if (ntohs(mac_header->typelen) == 0x0806)
   {
      eth_arp_respond();
   }
   else if (ntohs(mac_header->typelen) == 0x0800)
   {
      // IP packet
      t_ip_header *ip_rx_header = (t_ip_header *) eth_tx_mem;

      if (ip_rx_header->version == 0x45 && ip_rx_header->prot == 0x11)
      {
         // UDP packet
         t_udp_header *udp_rx_header = (t_udp_header *) eth_tx_mem;

         if (ntohs(udp_rx_header->dst) == 69 ||
             ntohs(udp_rx_header->dst) == 0x4A4D)
         {
            eth_tftp_respond();
         }
      }
   }
} // eth_respond


// Called when frame is ready for ROM to receive.
static void
eth_receive()
{
   uint16_t i;

   memcpy(eth_rx_mem, eth_buffer, 0x800);

   t_eth_header *eth_header = (t_eth_header *) eth_rx_mem;
   uint16_t len = eth_header->length;

   printf("eth_receive: ");

   for (i=0; i<0x800 && i<len+2; ++i)
   {
      printf("%02x ", eth_rx_mem[i]);
      if ((i&0xf) == 0xf)
      {
         printf("\n");
         printf("             ");
      }
   }
   printf("\n");
} // eth_receive



// Called when ROM has sent an ethernet frame
static void
eth_transmit()
{
   uint16_t i;

   t_eth_header *eth_header = (t_eth_header *) eth_tx_mem;
   uint16_t len = eth_header->length;

   printf("eth_transmit: ");

   for (i=0; i<0x800 && i<len+2; ++i)
   {
      printf("%02x ", eth_tx_mem[i]);
      if ((i&0xf) == 0xf)
      {
         printf("\n");
         printf("              ");
      }
   }
   printf("\n");

   eth_respond(); // Prepare response

} // eth_transmit


// Called once every clock cycle, i.e. after every 120 ns.
void
eth_step()
{
   if (eth_tx_own)
   {
      if (eth_tx_counter == 0)
      {
         eth_transmit();
         eth_tx_own = 0;
      }
      else
      {
         eth_tx_counter -= 1;
      }
   }

   if (eth_rx_own)
   {
      if (eth_rx_counter == 0)
      {
         if (eth_buffer_valid)
         {
            eth_receive();
            eth_rx_own = 0;
            eth_buffer_valid = false;
         }
      }
      else
      {
         eth_rx_counter -= 1;
      }
   }
} // eth_update

uint8_t
eth_read(uint8_t reg, bool debugOn)
{
   uint8_t value = 0;

   switch (reg) {
      case 0:
         value = eth_rx & 0xff;
         break;
      case 1:
         value = (eth_rx >> 8) & 0xff;
         break;
      case 2:
         value = eth_rx_mem[eth_rx];
         eth_rx = (eth_rx+1) & 0x7ff;
         break;
      case 3:
         value = eth_rx_own;
         break;

      case 8:
         value = eth_tx & 0xff;
         break;
      case 9:
         value = (eth_tx >> 8) & 0xff;
         break;
      case 10:
         value = eth_tx_mem[eth_tx];
         eth_tx = (eth_tx+1) & 0x7ff;
         break;
      case 11:
         value = eth_tx_own;
         break;
   }

   return value;
} // eth_read

void
eth_write(uint8_t reg, uint8_t value)
{
   switch (reg) {
      case 0:
         eth_rx = (eth_rx & 0xff00) | value;
         break;
      case 1:
         eth_rx = (eth_rx & 0x00ff) | (value << 8);
         break;
      case 2:
         eth_rx_mem[eth_rx] = value;
         eth_rx = (eth_rx+1) & 0x7ff;
         break;
      case 3:
         if ((eth_rx_own == 0) && ((value & 1) == 1)) {
            eth_rx_own = 1;
         }
         break;

      case 8:
         eth_tx = (eth_tx & 0xff00) | value;
         break;
      case 9:
         eth_tx = (eth_tx & 0x00ff) | (value << 8);
         break;
      case 10:
         eth_tx_mem[eth_tx] = value;
         eth_tx = (eth_tx+1) & 0x7ff;
         break;
      case 11:
         if ((eth_tx_own == 0) && ((value & 1) == 1)) {
            eth_tx_own = 1;
            eth_tx_counter = 200;   // Corresponds to 276 bytes of the MAC frame.
         }
         break;
   }
} // eth_write

