#ifndef DATA_H
#define DATA_H

#include <fstream>
#include <sstream>
#include <mutex>
#include <thread>
#include <array>
#include <stdio.h>
#include <cstdint>


#include <pcap.h>

#include <string>
#include <vector>
#include <iostream>

namespace DataCollection
{
    // Define the structure for the Ethernet header
    struct EthernetHeader {
        uint8_t destinationMac[6];  // Destination MAC address
        uint8_t sourceMac[6];       // Source MAC address
        uint16_t etherType;         // Ether Type (e.g., IPv4, ARP, etc.)
    };

    // Define the structure for the IP header
    struct IpHeader {
        uint8_t version;               // IP version (e.g., 4 for IPv4, 6 for IPv6)
        uint8_t headerLength;          // Header length in 32-bit words
        uint8_t tos;                   // Type of Service (TOS)
        uint16_t totalLength;          // Total length of the packet (header + data)
        uint16_t identification;       // Packet identification (used for fragmentation)
        uint16_t flagsFragmentOffset;  // Flags and Fragment Offset (used for fragmentation)
        uint8_t ttl;                   // Time to Live (TTL)
        uint8_t protocol;              // Protocol type (e.g., 6 for TCP, 17 for UDP)
        uint16_t headerChecksum;       // Header checksum
        std::string sourceIp;          // Source IP address (string representation)
        std::string destinationIp;     // Destination IP address (string representation)
    };

    // Define the structure for a network packet
    struct NetworkPacket {
        std::string networkInterface;      // Interface from which the packet is captured
        EthernetHeader ethernetHeader;    // Ethernet header
        IpHeader ipHeader;                // IP header
        uint16_t sourcePort;              // Source port (e.g., for TCP or UDP)
        uint16_t destinationPort;         // Destination port (e.g., for TCP or UDP)
        uint32_t sequenceNumber;          // Sequence number (e.g., for TCP)
        uint32_t acknowledgmentNumber;    // Acknowledgment number (e.g., for TCP)
        uint16_t flags;                   // Flags (e.g., for TCP)
        uint16_t checksum;                // Checksum (e.g., for TCP or UDP)
        std::vector<uint8_t> applicationData;  // Application layer data (payload)
        std::string timestamp;
        int packetNumber;
    };


    // Define a structure to represent endpoint data
    struct EndpointData {
        std::string endpointName;
        std::string hostname;
        std::string macAddress;
        std::string ipAddress;
        std::string operatingSystem;
        std::string userAccounts;
        std::vector<std::string> installedSoftware;
        std::string networkConnections;
        std::string securitySoftware;
        std::string hardwareInformation;
        std::string networkTraffic;
        std::string securityEvents;
        std::string location;
    };


    std::string NetworkScan(const std::string& target, const std::string& options);


    class LogCollector
    {
    private:
        std::string logFilePath;

    public:
        LogCollector(const std::string& logFilePath);
        std::string CollectData();
    };

    class MetadataCollector
    {
    public:
        MetadataCollector();
        std::string CollectData();
    };

    class PacketCollector
    {
    private:
        const std::vector<std::string>& networkInterfaces;
        int packetCount;

    public:
        PacketCollector(const std::vector<std::string>& networkInterfaces, int packetCount);
        std::vector<std::vector<NetworkPacket>> CollectData();
    };

    class EndpointDataCollector
    {
    private:
        std::string ipAddress;

    public:
        EndpointDataCollector(const std::string& ipAdrress);
        EndpointData CollectData();
    };
}

#endif // DATA_H
