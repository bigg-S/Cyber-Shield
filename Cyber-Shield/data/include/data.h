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

#include <typeinfo>

#include <condition_variable>
#include <atomic>
#include <csignal>

#include <WinSock2.h>

#include <chrono>
#include <random>
#include <random>

#include <pcap.h>

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
        int sourcePort = 0;
        int destinationPort = 0;
    };

    // Define the structure for the Ethernet header
    struct EthernetHeader 
    {
        uint8_t destinationMac[6];  // Destination MAC address
        uint8_t sourceMac[6];       // Source MAC address
        uint16_t etherType;         // Ether Type (e.g., IPv4, ARP, etc.)
    };

    // Define the structure for the IP header
    struct IpHeader
    {
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
    struct Packet
    {
        std::string networkInterface;     // Interface from which the packet is captured
        EthernetHeader ethernetHeader;    // Ethernet header
        IpHeader ipHeader;                // IP header
        uint16_t sourcePort = 0;              // Source port (e.g., for TCP or UDP)
        uint16_t destinationPort = 0;         // Destination port (e.g., for TCP or UDP)
        uint32_t sequenceNumber;          // Sequence number (e.g., for TCP)
        uint32_t acknowledgmentNumber;    // Acknowledgment number (e.g., for TCP)
        uint16_t flags = 0;                   // Flags (e.g., for TCP)
        uint16_t checksum;                // Checksum (e.g., for TCP or UDP)
        const u_char* payload;  // Application layer data (payload)
        std::string timestamp;
        std::string protocol_type;
        uint8_t ttl = 0;
        uint32_t sourceIp;
        uint32_t destIp;
    };

    // a connection
    struct Connection 
    {
        uint32_t sourceIP;
        uint16_t sourcePort;
        uint32_t destIP;
        uint16_t destPort;
        std::string flags;
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

        std::vector<std::thread> threads;

        std::mutex capturedPacketsMutex;
        std::mutex instanceMutex;
        std::mutex startMutex;
        std::mutex isCapturingMutex;
        std::mutex connTable;

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
        Datapoint AttributeExtractor(const u_char*, Packet, const struct pcap_pkthdr&, const u_char*, int, int, uint8_t, uint16_t, uint16_t);
        static void StaticSignalHandler(int signal); // static function to serve as an inermediary to call the non-static SignalHandler functio
        void SignalHandler(int signal);
        std::map<std::string, std::vector<Packet>> GetCapturedPackets();
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