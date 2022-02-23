#pragma once

typedef unsigned char	u_char;		//1Byte
typedef unsigned short	u_short;	//2Byte
typedef unsigned int	u_int;		//4Byte
typedef unsigned long	u_long;		//4Byte

#define ARP "ARP"
#define TCP "TCP"
#define UDP "UDP"
#define ICMP "ICMP"
#define DNS "DNS"
#define TLS "TLS"
#define SSL "SSL"

/**EtherNet header
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        48bit(6Byte)         |        48bit(6Byte)  |  16bit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Destination MacAddr    |    Source MacAddr    |   type   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct Ethernet_Header
{
    u_char ether_dst_host[6];
    u_char ether_src_host[6];
    u_short type;
}ETHERNET_HEADER, Ethernet_Header;

/**IPv4 header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct IPv4_Header
{
    u_char version_IHL;    // version [4 bit] and length of header [4 bit]
    u_char TOS;                     // Type of Service/DS_byte [1 byte]
    u_short total_length;           // ip package total length [2 byte]
    u_short identification;         // identification [2 byte]
    u_short flag_offset;            // flag [3 bit] and offset [13 bit]
    u_char ttl;                     // TTL [1 byte]
    u_char protocol;                // protocal [1 byte]
    u_short checksum;               // checksum [2 byte]
    u_int src_addr;                 // source address [4 byte]
    u_int des_addr;                 // destination address [4 byte]
}IPv4_Header, IPV4_HEADER;

/**TCP header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|E|R|S|F|                               |
   | Offset| Reserved  |R|C|O|S|Y|I|            Window             |
   |       |           |G|K|L|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct TCP_Header
{
    u_short src_port;         // source port [2 byte]
    u_short dst_port;         // destination [2 byte]
    u_int sequence;           // sequence number [4 byte]
    u_int ack;                // Confirm serial number [4 byte]
    u_char header_length;     // header length [4 bit]
    u_char flags;             // flags [6 bit]
    u_short window_size;      // size of window [2 byte]
    u_short checksum;         // checksum [2 byte]
    u_short urgent;           // urgent pointer [2 byte]

}TCP_Header, TCP_HEADER;


/**UDP header
    0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |          source address           |
    +--------+--------+--------+--------+
    |        destination address        |
    +--------+--------+--------+--------+
    |  zero  |protocol|   UDP length    |
    +--------+--------+--------+--------+
*/
typedef struct UDP_Header
{
    u_short src_port;      // source port [2 byte]
    u_short dst_port;      // destination port [2 byte]
    u_short data_length;   // data length [2 byte]
    u_short checksum;      // checksum [2 byte]
}UDP_Header, UDP_HEADER;

/**ICMP header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct ICMP_Header {
    u_char type;                    // type [1 byte]
    u_char code;                    // code [1 byte]
    u_short checksum;               // checksum [2 byte]
    u_short identification;         // identification [2 byte]
    u_short sequence;               // sequence [2 byte]
}ICMP_Header, ICMP_HEADER;

//Arp
/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
typedef struct Arp_Header {   // 28 byte
    u_short hardware_type;   // hardware type [2 byte]
    u_short protocol_type;   // protocol [2 byte]
    u_char mac_length;       // MAC address length [1 byte]
    u_char ip_length;        // IP address length [1 byte]
    u_short op_code;         // operation code [2 byte]

    u_char src_eth_addr[6];  // source ether address [6 byte]
    u_char src_ip_addr[4];   // source ip address [4 byte]
    u_char des_eth_addr[6];  // destination ether address [6 byte]
    u_char des_ip_addr[4];   // destination ip address [4 byte]

}Arp_Header, ARP_HEADER;

// dns
/*
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
*/
typedef struct DNS_Header {  // 12 byte
    u_short identification; // Identification [2 byte]
    u_short flags;          // Flags [total 2 byte]
    u_short question;       // Question Number [2 byte]
    u_short answer;         // Answer RRs [2 byte]
    u_short authority;      // Authority RRs [2 byte]
    u_short additional;     // Additional RRs [2 byte]
}DNS_Header, DNS_HEADER;

// dns question
typedef struct DNS_Question {
    // char* name;          // Non-fixed
    u_short query_type;     // 2 byte
    u_short query_class;    // 2 byte
}DNS_Question, DNS_QUESITON;

typedef struct DNS_Answer {
    // char* name          // Non-fixed
    u_short answer_type;   // 2 byte
    u_short answer_class;  // 2 byte
    u_int TTL;             // 4 byte
    u_short dataLength;    // 2 byte
    //char* name           // Non-fixed
}DNS_Answer, DNS_ANSWER;



