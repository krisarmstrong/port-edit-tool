// Filename: voip_port_edit.cpp
// Revision: 11/17/2011
//
// Description:
//   C program to parse a Wireshark LAN capture file and calculate VoIP stats
//   for UDP frames containing SIP/RTP/RTCP info. If optional oldPort and newPort
//   are specified by user, perform substitution when a match on oldPort is found.
//
// To Build using Visual C++ 2008 Express command-line compiler:
//   cl voip_port_edit.cpp
//
// To Run:
//   voip_port_edit.cpp <capture_file> [oldPort] [newPort]
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION "dev"
#endif

#define MOD_FILENAME "port_mod.pcap"

#define MAX_BUF_SIZE 500000 // was 100000
#define FILE_HEADER_SIZE   24
#define RECORD_HEADER_SIZE 16
#define REC_OFFSET_BYTES   8

#define MIN_FRAME_LEN 42 // broadcast ARP

#define FRAME_OFFSET_ETHTYPE  0x0c
#define FRAME_OFFSET_PROTOCOL 0x17 // 23 dec
#define FRAME_OFFSET_UDP_SRC_PORT 0x22 // 34 dec
#define FRAME_OFFSET_UDP_DST_PORT 0x24 // 36 dec

#define ETHTYPE_IP  0x0800
#define ETHTYPE_ARP 0x0806
#define ETHTYPE_IPX 0x8137

#define UDP_PROTOCOL  17
#define TCP_PROTOCOL  6
#define ICMP_PROTOCOL 1

#define SIP_PORT 5060
#define FTP_PORT 21 // TCP
#define DNS_PORT 53
#define BOOTPS_PORT 67
#define BOOTPC_PORT 68
#define NETBIOS_NS_PORT  137
#define NETBIOS_BR_PORT  138
#define NETBIOS_SSN_PORT 139
#define SMART_DIAG_PORT  2721 // TCP
#define FLUKE_TPUT_PORT 3842 // UDP


int getWordSwapped(unsigned char *pWord)
{
    int val = (pWord[1] << 8) + pWord[0];
    return val;
}

int getWord(unsigned char *pWord)
{
    int val = (pWord[0] << 8) + pWord[1];
    return val;
}

void putWord(int srcPort, unsigned char *pWord)
{
    unsigned char lowerByte = srcPort & 0xFF;
    unsigned char upperByte = (srcPort >> 8) & 0xFF;
    pWord[0] = upperByte;
    pWord[1] = lowerByte;
}

int main(int argc, char *argv[])
{
    if ( argc < 2 )
    {
        //fprintf(stderr,"error: no filename specified\n");
        fprintf(stderr, "VoIP stats and Port Edit tool - version %s\n", PROGRAM_VERSION);
        fprintf(stderr, "usage: %s <wireshark_pcap_file> [oldPort] [newPort]\n", argv[0]);
        return 1;
    }

    FILE *infile = fopen( argv[1], "rb" );
    if ( infile == NULL )
    {
        fprintf(stderr,"error: filename not found\n");
        return 1;
    }

    bool bSubstitutePorts = false;
    int oldPort = 0;
    int newPort = 0;

    if ( argc >= 3 )
    {
        oldPort = atoi(argv[2]);
        if ( argc >= 4 )
        {
            newPort = atoi(argv[3]);
            bSubstitutePorts = true;
        }
    }

    int c = 0;
    int k = 0;
    unsigned char buf[MAX_BUF_SIZE] = {0};
    while ( (c = fgetc(infile)) != EOF )
    {
        buf[k++] = c & 0xff;
        if ( k >= MAX_BUF_SIZE )
        {
            fprintf(stderr,"warning: exceeded buffer size\n");
            break;
        }
    }
    fclose(infile);
    int filesize = k;
    printf("filename= %s\n", argv[1]);
    printf("filesize= %d bytes\n", filesize);
    printf("\n");

    // parse all records...
    int recCnt = 0;
    int rtpPort = 0;
    int rtcpPort = 0;
    k = FILE_HEADER_SIZE;

    int sipCnt = 0;
    int rtpCnt = 0;
    int rtcpCnt = 0;

    while ( k < filesize )
    {
        int frameLen = getWordSwapped(&buf[k + REC_OFFSET_BYTES]); // bytes on wire ??
        printf("id=%03d: bytes=%4d", recCnt+1, frameLen);
        k += RECORD_HEADER_SIZE;
        
        if ( frameLen < MIN_FRAME_LEN )
        {
            printf(" [Malformed Packet]\n"); // too short 
        }
        else
        {
            int ethType = getWord( &buf[k+FRAME_OFFSET_ETHTYPE] );
            if ( ethType != ETHTYPE_IP )
            {
                if ( ethType == ETHTYPE_ARP )
                {
                    printf(" ARP");
                }
                else if ( ethType == ETHTYPE_IPX )
                {
                    printf(" IPX"); // Netware IPX/SPX
                }
                else
                {
                    printf(" ethType=0x%04x ??", ethType);
                }
                //printf(" non-IP\n");
                printf("\n");
            }
            else
            {
                int ipType = buf[k+FRAME_OFFSET_PROTOCOL];
                //printf(" Type=");
                printf(" ");

                if ( ipType == UDP_PROTOCOL )
                {
                    printf("UDP ");
                }
                else if ( ipType == TCP_PROTOCOL )
                {
                    printf("TCP ");
                }
                else if ( ipType == ICMP_PROTOCOL )
                {
                    printf("ICMP");
                }
                else
                {
                    printf("%d", ipType);
                    //printf("<un>");
                }

                if ( ipType == UDP_PROTOCOL || ipType == TCP_PROTOCOL )
                {
                    int srcPort = getWord(&buf[k+FRAME_OFFSET_UDP_SRC_PORT]);
                    int dstPort = getWord(&buf[k+FRAME_OFFSET_UDP_DST_PORT]);
                    printf(" srcPort=%4d dstPort=%4d ", srcPort, dstPort);

                    //if ( ipType == UDP_PROTOCOL )
                    {
                        printf(" proto=");
                        if ( srcPort == SIP_PORT || dstPort == SIP_PORT )
                        {
                            sipCnt++;
                            printf("SIP");

                            char szSipOk[]     = "SIP/2.0 200 OK";
                            char szSipInBand[] = "SIP/2.0 183 In band";
                            bool bExtractRtp = false;

                            if ( strncmp((char*)(&buf[k+0x2a]), szSipOk, strlen(szSipOk) ) == 0 )
                            {
                                printf("-ok");
                                bExtractRtp = true;
                            }
                            if ( strncmp((char*)(&buf[k+0x2a]), szSipInBand, strlen(szSipInBand) ) == 0 )
                            {
                                // special case found in file "aaa_sip_with_rtp.pcap"
                                printf("-inband");
                                bExtractRtp = true;
                            }
                            if ( bExtractRtp )
                            {
                                char szMediaTypeAudio[] = "m=audio ";
                                char *pMedia = strstr((char*)(&buf[k+0x2a]), szMediaTypeAudio);
                                if ( pMedia )
                                {
                                    pMedia += strlen(szMediaTypeAudio);
                                    rtpPort = atoi(pMedia);
                                    rtcpPort = rtpPort + 1;
                                    printf(" RTP=%d", rtpPort);
                                }
                            }
                        }
                        else if ( rtpPort > 0 && (srcPort == rtpPort || dstPort == rtpPort) )
                        {
                            rtpCnt++;
                            printf("RTP");
                        }
                        else if ( rtcpPort > 0 && (srcPort == rtcpPort || dstPort == rtcpPort) )
                        {
                            rtcpCnt++;
                            printf("RTCP");
                        }
                        else if ( srcPort == NETBIOS_NS_PORT || dstPort == NETBIOS_NS_PORT )
                        {
                            printf("NB-NAMESERV");
                        }
                        else if ( srcPort == NETBIOS_BR_PORT || dstPort == NETBIOS_BR_PORT )
                        {
                            printf("NB-BROWSER");
                        }
                        else if ( srcPort == NETBIOS_SSN_PORT || dstPort == NETBIOS_SSN_PORT )
                        {
                            printf("NB-SSN");
                        }
                        else if ( srcPort == DNS_PORT || dstPort == DNS_PORT )
                        {
                            printf("DNS");
                        }
                        else if ( dstPort == BOOTPC_PORT || dstPort == BOOTPS_PORT )
                        {
                            printf("DHCP");
                        }
                        else if ( srcPort == FTP_PORT || dstPort == FTP_PORT )
                        {
                            printf("FTP"); // TCP only
                        }
                        else if ( srcPort == SMART_DIAG_PORT || dstPort == SMART_DIAG_PORT )
                        {
                            printf("Smart-Diag"); // TCP only
                        }
                        else if ( srcPort == FLUKE_TPUT_PORT || dstPort == FLUKE_TPUT_PORT )
                        {
                            printf("Fluke-Tput"); // UDP only
                        }
                        else
                        {
                            printf("unknown");
                        }
                        if ( bSubstitutePorts )
                        {
                            // KLL_TODO:
                            if ( srcPort == oldPort )
                            {
                                srcPort = newPort;
                                putWord(srcPort, &buf[k+FRAME_OFFSET_UDP_SRC_PORT]);
                            }
                            if ( dstPort == oldPort )
                            {
                                dstPort = newPort;
                                putWord(dstPort, &buf[k+FRAME_OFFSET_UDP_DST_PORT]);
                            }
                            // KLL_TODO:
                        }
                    } // UDP_PROTOCOL
                } // UDP or TCP
                printf("\n");
            } // else ethType == ETHTYPE_IP
        } // else length >= MIN_FRAME_LEN

        k += frameLen;
        recCnt++;
    }

    // summary
    fprintf(stderr, "\n");
    fprintf(stderr, "VoIP Summary: \n");
    fprintf(stderr, "SIP pkts= %d\n", sipCnt);
    fprintf(stderr, "RTP pkts= %d\n", rtpCnt);
    fprintf(stderr, "RTCP pkts= %d\n", rtcpCnt);

    if ( bSubstitutePorts )
    {
        FILE *outfile = fopen(MOD_FILENAME, "wb");
        if ( outfile == NULL )
        {
            return 1;
        }
        for ( k = 0; k < filesize; k++ )
        {
            fputc(buf[k], outfile);
        }
        fclose(outfile);
        fprintf(stderr, "\n");
        fprintf(stderr, "output file: %s\n", MOD_FILENAME);
    }

    return 0;
}
// <end-of-file>
