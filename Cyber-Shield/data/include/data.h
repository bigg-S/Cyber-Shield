#ifndef DATA_H
#define DATA_H

#include "boost/archive/text_iarchive.hpp"
#include "boost/archive/text_oarchive.hpp"
#include "boost/serialization/shared_ptr.hpp"
#include "boost/serialization/vector.hpp"

#include <fstream>
#include <sstream>
#include <stdio.h>
#include <stdint.h>
#include <cstdint>
#include <cmath>

#include <memory>
#include <mutex>
#include <thread>
#include <shared_mutex>

#include <typeinfo>

#include <condition_variable>
#include <atomic>
#include <csignal>

#include <WinSock2.h>
#include <iphlpapi.h>

#include <chrono>
#include <ctime>
#include <random>
#include <random>

#include <pcap.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <iostream>
#include <array>
#include <unordered_map>
#include <unordered_set>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

namespace DataCollection
{
    // Ethernet header
    struct ETHER_HEADER 
    {
        UCHAR ether_dhost[6];   // Destination MAC address
        UCHAR ether_shost[6];   // Source MAC address
        USHORT ether_type;      // Ethernet type
    };

    // Define the IP header structure for Windows
    struct IP 
    {
        #if defined(_WIN32)
            unsigned char ip_vhl;         // version << 4 | header length >> 2
            unsigned char ip_tos;         // type of service
            short ip_len;                 // total length
            unsigned short ip_id;         // identification
            short ip_off;                 // fragment offset field
        #define IP_RF 0x8000              // reserved fragment flag
        #define IP_DF 0x4000              // dont fragment flag
        #define IP_MF 0x2000              // more fragments flag
            unsigned char ip_ttl;         // time to live
            unsigned char ip_p;           // protocol
            unsigned short ip_sum;        // checksum
            struct in_addr ip_src, ip_dst; // source and dest address
        #else
        #endif
    };

    // IPV6 packet header
    struct IPV6_HEADER 
    {
        uint8_t versionTrafficClass[4]; // 4 bits version, 8 bits traffic class, 20 bits flow label
        uint16_t payloadLength;         // Payload length
        uint8_t nextHeader;             // Protocol type following IPv6 header
        uint8_t hopLimit;               // TTL
        struct in6_addr sourceIPv6;     // Source IPv6 address
        struct in6_addr destIPv6;       // Destination IPv6 address
    };

    // TCP header
    struct TCP 
    {
            u_short th_sport;	/* source port */
            u_short th_dport;	/* destination port */
            u_int th_seq;		/* sequence number */
            u_int th_ack;		/* acknowledgement number */
            u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
            u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
            u_short th_win;		/* window */
            u_short th_sum;		/* checksum */
            u_short th_urp;		/* urgent pointer */
    };

    // the UDP header structure
    struct UDP 
    {
        unsigned short source_port;   // Source port
        unsigned short dest_port;     // Destination port
        unsigned short length;        // Datagram length
        unsigned short checksum;      // Checksum
    };

    // the ICMP header structure
    struct ICMP 
    {
        unsigned char type;           // ICMP message type
        unsigned char code;           // Sub-code
        unsigned short checksum;      // Checksum
        unsigned short id;            // Identifier (used in some ICMP messages)
        unsigned short sequence;      // Sequence Number (used in some ICMP messages)
        // Additional fields depending on the ICMP message type
    };

    // For wi-fi frames
    // Management frame header
    struct ManagementFrameHeader 
    {
        uint16_t frameControl;
        uint16_t duration;
        uint8_t receiverAddress[6];
        uint8_t transmitterAddress[6];
        uint8_t destinationAddress[6];
        uint16_t fragmentNumber : 4;
        uint16_t sequenceNumber : 12;
    };

    // Control frame header
    struct ControlFrameHeader 
    {
        uint16_t frameControl;
        uint16_t duration;
        uint8_t receiverAddress[6];
        uint8_t transmitterAddress[6];
    };

    // Data frame header
    struct DataFrameHeader 
    {
        uint16_t frameControl;
        uint16_t duration;
        uint8_t receiverAddress[6];
        uint8_t transmitterAddress[6];
        uint8_t destinationAddress[6];
        uint16_t fragmentNumber : 4;
        uint16_t sequenceNumber : 12;
    };

    // An item for the machine learning model
    struct Datapoint
    {
        int duration = 0;        
        std::string protocol_type = "";
        std::string service = "";
        std::string flag = "";
        int src_bytes = 0;
        int dst_bytes = 0;
        int land = 0;
        int wrong_fragment = 0;
        int urgent = 0;                
        int hot = 0;
        int num_failed_logins = 0;
        int logged_in = 0;
        int num_compromised = 0;
        int root_shell = 0;
        int su_attempted = 0;
        int num_root = 0;
        int num_file_creations = 0;
        int num_shells = 0;
        int num_access_files = 0;
        int num_outbound_cmds = 0;
        int is_host_login = 0;
        int is_guest_login = 0;
        int count = 0;
        int srv_count = 0;
        double serror_rate = 0.0;
        double srv_serror_rate = 0.0;
        double rerror_rate = 0.0;
        double srv_rerror_rate = 0.0;
        double same_srv_rate = 0.0;
        double diff_srv_rate = 0.0;
        double srv_diff_host_rate = 0.0;
        int dst_host_count = 0;
        int dst_host_srv_count = 0;
        double dst_host_same_srv_rate = 0.0;
        double dst_host_diff_srv_rate = 0.0;
        double dst_host_same_src_port_rate = 0.0;
        double dst_host_srv_diff_host_rate = 0.0;
        double dst_host_serror_rate = 0.0;
        double dst_host_srv_serror_rate = 0.0;
        double dst_host_rerror_rate = 0.0;
        double dst_host_srv_rerror_rate = 0.0;
    };

    // Packet structure
    struct Packet
    {
        struct in_addr ip_src;
        struct in_addr ip_dst;
        struct in6_addr ip6_src;
        struct in6_addr ip6_dst;
        unsigned short source_port;
        unsigned short dest_port;
        unsigned char ip_ttl;
        unsigned char ip_p;
        u_char flags;
        std::string timestamp;
        const UCHAR* payload;
        std::string protocol_type;
    };

    // a connection
    struct Connection 
    {
        struct in_addr ip_src;
        struct in_addr ip_dst;
        struct in6_addr ip6_src;
        struct in6_addr ip6_dst;
        u_short sport;
        u_short dport;
        u_char flags;
        std::string timestamp;
        std::string payloadString;
    };

    // Define a structure to represent endpoint data
    struct EndpointData
    {
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

    // **************Properties of a network interface*****************//
    struct NetworkStatistics
    {
        int packetsTransmitted;
        int packetsReceived;
        int errors;
    };

    struct VLANConfig
    {
        std::string vlanId;
        std::string vlanName;
    };

    struct FirewallSettings
    {
        bool enabled;
        std::string ruleSet;
    };

    struct Ipv6Settings
    {
        std::string ipv6Address;
        std::string ipv6Gateway;
    };

    struct WirelessProperties
    {
        std::string ssid;
        std::string signalStrength;
        std::string encryptionType;
    };

    // **************End of Properties of a network interface*****************//

    // Network interface
    struct NetworkInterface
    {
        std::string interfaceName;
        std::string interfaceType;
        std::string macAddress;
        std::string ipAddress;
        std::string subnetMask;
        std::string defaultGateway;
        std::string dnsIp;
        std::string maxTransmissionUnit;
        std::string speed;
        std::string state;
        std::string interfaceDescription;
        pcap_t* pcapHandle = nullptr;

        NetworkStatistics networkStatistics;
        VLANConfig vlanConfig;
        FirewallSettings firewallSettings;
        Ipv6Settings ipv6Settings;
        WirelessProperties wirelessProperties;
    };

    // logic to create a log file for the network
    class NetworkLogger
    {
    private:
        std::ofstream logFile;

    public:
        NetworkLogger(const std::string& logFileName);

        ~NetworkLogger();

        void Log(const std::string logMessage);
    };

    // collecting network extra data
    class NetworkHelperFunctions
    {
    private:
        const std::string& ipAddress;
        const std::string& networkId;
        const std::string& subnetMask;
        pcap_if_t* dev;
        const std::string& target;
        const std::string& options;
        NetworkLogger& logger;
    public:
        NetworkHelperFunctions(const std::string& ipAddress, const std::string& networkId, const std::string& subnetMask, pcap_if_t* dev, const std::string& target, const std::string& options, NetworkLogger& logger);

        bool IsIpAddressInNetwork(const std::string& ipAddress, const std::string& networkId, const std::string& subnetMask);
        std::vector<NetworkInterface> GetNetworkInterfaces();
        std::string NetworkScan(const std::string& target, const std::string& options);
    };


    // collecting network packets
    class PacketCollector
    {
    private:
        // Constants for header sizes
        const int ETHERNETHEADERSIZE = 14;
        const int WIFIHEADERSIZE = 24;
        const int IPV4HEADERSIZE = 20;
        const int IPV6HEADERSIZE = 40;

        enum LinkType 
        {
            ETHERNETFRAME = DLT_EN10MB,
            WIFIFRAME = DLT_IEEE802_11
        };

        const std::vector<NetworkInterface>& networkInterfaces;        
        std::map<std::string, std::vector<Packet>> capturedPackets;
        // store captured packets
        std::vector<Packet> capturedPacketsArr;
        std::vector<Connection> connectionsTable;
        std::vector<Datapoint> datapoints;

        std::vector<std::thread> threads;

        std::mutex capturedPacketsMutex;
        std::mutex instanceMutex;
        std::mutex startMutex;
        std::mutex isCapturingMutex;
        std::mutex connTable;
        std::mutex datapointMutex;
        std::mutex connectionsMutex;
        std::mutex connectionsMutex1;


        std::condition_variable startCV;  //global condition variable for synchronization

        std::atomic<int> startBarrier = 0; // Barrier to synchronise thread start
        std::atomic<bool> isCapturing{ false }; // global flag to stop packet capturre        

        static PacketCollector* instance; //static pointer to an instance
        
        // Global flag to determine whether the program should terminate
        volatile sig_atomic_t g_programShouldExit = 0;

        NetworkLogger& logger;

        void ProcessPacket(const u_char* packetData, const struct pcap_pkthdr& header, const NetworkInterface& iface, std::chrono::system_clock::time_point capturStartTime);

    public:
        PacketCollector(const std::vector<NetworkInterface>& networkInterfaces, NetworkLogger& logger);
        ~PacketCollector();

        uint32_t bytesToUint32(const uint8_t* bytes);
        void StartCapture();
        void StopCapture();
        void CapturePackets(const NetworkInterface& iface);
        int countConnectionsToSameService(const Packet& currentConnection, std::vector<Connection>& connections, int numConnections);
        int countConnectionsToSameDestination(const Packet& currentConnection, std::vector<Connection>& connections, int numConnections);
        std::string ConvertIPv6AddressToString(const uint8_t* ipv6Address);
        Datapoint AttributeExtractor(const u_char*, Packet, const struct pcap_pkthdr&, const IP*, int, int, uint8_t, uint16_t, uint16_t);
        static void StaticSignalHandler(int signal); // static function to serve as an inermediary to call the non-static SignalHandler functio
        void SignalHandler(int signal);
        std::map<std::string, std::vector<Packet>> GetCapturedPackets();
        std::vector<Datapoint> GetDatapoints();
    };


    // collecting network endpoint data
    class EndpointDataCollector
    {
    private:
        std::string ipAddress;
        NetworkLogger& logger;

    public:
        EndpointDataCollector(const std::string& ipAdrress, NetworkLogger& logger);
        EndpointData CollectData();
    };

    // collecting network metadata
    class MetadataCollector
    {
    private:
        NetworkLogger& logger;
    public:
        MetadataCollector(NetworkLogger& logger);
        std::string CollectData();
    };

    // collecting network logs
    class LogCollector
    {
    private:
        std::string logFilePath;

    public:
        LogCollector(const std::string& logFilePath);
        std::string CollectData();
    };

    // data preprocessing
    class Data
    {
        std::shared_ptr<std::vector<double>> featureVector; // no class at the end of the record
        std::string label;
        int enumLabel;
        double distance;

    public:
        Data();
        ~Data();

        template<class Archive>
        void serialize(Archive& ar, const unsigned int);

        void SetFeatureVector(std::shared_ptr<std::vector<double>>);
        void AppendToFeatureVector(const double&); 
        void SetLabel(std::string);
        void SetEnumLabel(int);

        int GetFeatureVectorSize();
        std::string GetLabel();
        int GetEnumLabel();
        double GetDistance();

        std::shared_ptr<std::vector<double>> GetFeatureVector();

        void SetDistance(double val);
    };

    // Data handler (implements logic to read in, spil, count unique classes, pass aroud all kinds of data)
    class DataHandler
    {
        std::shared_ptr<std::vector<std::shared_ptr<Data>>> dataArray; // all of the data pre-split
        std::shared_ptr<std::vector<std::shared_ptr<Data>>> trainingData;
        std::shared_ptr<std::vector<std::shared_ptr<Data>>> testData;
        std::shared_ptr<std::vector<std::shared_ptr<Data>>> validationData;

        int numClasses; // number of classes we have
        int featureVectorSize;
        std::map<std::string, int> classMap; // storing a class label to it's enumerated value 

        // in order to split data
        const double TRAIN_SET_PERCENT = 0.75;
        const double TEST_SET_PERCENT = 0.20;
        const double VALIDATION_PERCENT = 0.05;

    public:
        DataHandler();
        ~DataHandler();

        // Data serialization
        template<class Archive>
        void serialize(Archive& ar, const unsigned int);
        void SaveDataHandler(std::string& fileName);
        void LoadDataHandler(std::string& fileName);

        void ReadFeatureVector(std::string path);
        void ReadFeatureLabels(std::string path);
        void SplitData();
        void CountClasses();

        std::shared_ptr<std::vector<std::shared_ptr<Data>>> GetTrainingData();
        std::shared_ptr<std::vector<std::shared_ptr<Data>>> GetTestData();
        std::shared_ptr<std::vector<std::shared_ptr<Data>>> GetValidationData();
    };
}

#endif // DATA_H