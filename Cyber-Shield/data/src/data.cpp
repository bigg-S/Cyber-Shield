#include "ml_model.h"

namespace DataCollection
{
    // create log file to store network logs and data    
    NetworkLogger::NetworkLogger(const std::string& logFileName)
    {
        logFile.open(logFileName, std::ios::app); // open log file in append mode
        if (!logFile.is_open())
        {
            throw std::runtime_error("Failed to open log file.");
        }
    }

    NetworkLogger::~NetworkLogger()
    {
        if (logFile.is_open())
        {
            logFile.close();
        }
    }

    void NetworkLogger::Log(const std::string logMessage)
    {
        if (logFile.is_open())
        {
            logFile << logMessage << std::endl;
        }
        else
        {
            std::cerr << "Error: Log file is not open" << std::endl;
        }
    }

    // Network helper functions initializations
    NetworkHelperFunctions::NetworkHelperFunctions(const std::string& ipAddress, const std::string& networkId, const std::string& subnetMask, pcap_if_t* dev, const std::string& target, const std::string& options, NetworkLogger& logger)
        : ipAddress(ipAddress), networkId(networkId), subnetMask(subnetMask), dev(dev), target(target), options(options), logger(logger) {}

    // define a function for performing network scanning using nmap
    std::string NetworkHelperFunctions::NetworkScan(const std::string& target, const std::string& options)
    {
        try
        {
            // initialize a buffer to store the PATH variable value
            char* pathBuffer = nullptr;
            size_t requiredSize;

            // Use _dupenv_s to get the value of the PATH variable
            if (_dupenv_s(&pathBuffer, &requiredSize, "PATH") == 0 && pathBuffer != nullptr)
            {
                // successfully retrieved the path variable value
                std::string originalPath(pathBuffer);

                // now the original path can be modified as needed

                // free the allocated buffer when done
                free(pathBuffer);
            }
            else
            {
                // Handle the case where _dupenv_s fails to retrieve the PATH variable
                //You can provide a default PATH value or handle the error accordingly
                //std::cerr << "Failed to retrieve the PATH variable." << std::endl;
                logger.Log("Failed to retrieve the PATH variable.");
            }

            // build the nmap command
            std::string command = "nmap " + options + " " + target;

            // open a pipe to run the command and capture the output
            std::array<char, 128> buffer{};
            std::string result;
            std::shared_ptr<FILE> pipe(_popen(command.c_str(), "r"), _pclose);
            if (!pipe)
            {
                throw std::runtime_error("popen() failed");
            }

            // read the output of the command into the result string
            while (!feof(pipe.get()))
            {
                if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
                {
                    result += buffer.data();
                }
            }

            return result;

        }
        catch (const std::exception& e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
            logger.Log("Error: Network scan failed");
            return "Error: Network scan failed";
        }
    }

    // find out if an ip address is in the network
    bool NetworkHelperFunctions::IsIpAddressInNetwork(const std::string& ipAddress, const std::string& networkIdentifier, const std::string& subnetMask)
    {
        if (ipAddress.find(':') != std::string::npos)
        {
            // Handle IPv6 addresses

            // Parse the IP address, network identifier, and subnet mask into their numeric representations
            in6_addr ipAddr, netID, subnet;
            inet_pton(AF_INET6, ipAddress.c_str(), &ipAddr);
            inet_pton(AF_INET6, networkIdentifier.c_str(), &netID);
            inet_pton(AF_INET6, subnetMask.c_str(), &subnet);

            // Initialize a result buffer for bitwise operations
            uint8_t result[16];

            // Perform bitwise AND operation between the IP address and subnet mask
            for (int i = 0; i < 16; ++i)
            {
                result[i] = ipAddr.s6_addr[i] & subnet.s6_addr[i];
            }

            // Check if the result matches the network identifier
            if (memcmp(result, netID.s6_addr, 16) == 0)
            {
                return true;
            }
        }
        else
        {
            // Handle IPv4 addresses

            // Parse the IP address, network identifier, and subnet mask into their numeric representations
            in_addr ipAddr, netID, subnet;
            inet_pton(AF_INET, ipAddress.c_str(), &ipAddr);
            inet_pton(AF_INET, networkIdentifier.c_str(), &netID);
            inet_pton(AF_INET, subnetMask.c_str(), &subnet);

            // Perform bitwise AND operation between the IP address and subnet mask
            uint32_t ipAddrNumeric = ntohl(ipAddr.s_addr);
            uint32_t netIDNumeric = ntohl(netID.s_addr);
            uint32_t subnetNumeric = ntohl(subnet.s_addr);

            if ((ipAddrNumeric & subnetNumeric) == (netIDNumeric & subnetNumeric))
            {
                return true;
            }
        }

        return false;
    }

    // retrieve a device's network interfaces
    std::vector<NetworkInterface> NetworkHelperFunctions::GetNetworkInterfaces()
    {
        std::vector<NetworkInterface> networkInterfaces;

        pcap_if_t* allDevs;
        char errbuf[PCAP_ERRBUF_SIZE];

        //retrieve the list of network interfaces
        if (pcap_findalldevs(&allDevs, errbuf) == -1)
        {
            logger.Log(errbuf);
            std::cerr << "Failed to retrieve network interfaces" << errbuf << std::endl;
            return networkInterfaces;
        }

        pcap_if_t* dev;
        int i = 0;

        // iterate through the list of network interfaces
        for (dev = allDevs; dev != NULL; dev = dev->next)
        {
            NetworkInterface networkInterface;
            networkInterface.interfaceName = dev->name;
            networkInterface.interfaceDescription = dev->description ? dev->description : "N/A";
            networkInterfaces.push_back(networkInterface);
        }

        // free the list of network interfaces
        pcap_freealldevs(allDevs);

        return networkInterfaces;
    }

    // collecting information about network adapters
    MetadataCollector::MetadataCollector(NetworkLogger& logger) : logger(logger) {}

    std::string MetadataCollector::CollectData() {
        try
        {
            // a string to hold the metadata
            std::stringstream metadata;

            // open an Npcap session to query network information
            pcap_if_t* allDevs; // to store network adapter information
            char errbuf[PCAP_ERRBUF_SIZE];

            if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &allDevs, errbuf) == -1)
            {
                logger.Log("Error: Failed to find network adapters " + std::string(errbuf));
                std::cerr << "Error: Failed to find network adapters" << errbuf << std::endl;
                return "Error: Network data collection failed";
            }

            // iterate through network adapters and collect metadata
            int adapterCount = 1;
            for (pcap_if_t* device = allDevs; device != nullptr; device = device->next)
            {
                metadata << "Adapter" << adapterCount << ":\n";
                metadata << " - Name: " << device->name << "\n";
                if (device->description)
                {
                    metadata << " - Description: " << device->description << "\n";
                }
                metadata << " - Loopback: " << ((device->flags & PCAP_IF_LOOPBACK) ? "Yes" : "No") << "\n";

                adapterCount++;
            }

            // release the list of network adapters
            pcap_freealldevs(allDevs);

            // return the collected metadata as a string
            return metadata.str();
        }
        catch (const std::exception& e)
        {
            // handle necessary exception
            logger.Log("Error: Error during metadata collection: " + std::string(e.what()));
            //std::cerr << "Error: Error during metadata collection: " << e.what() << std::endl;
            return "Error: Metadata collection failed";
        }
    }

    // packet capture init

    // define the static instance member
    PacketCollector* PacketCollector::instance = nullptr;

    PacketCollector::PacketCollector(const std::vector<NetworkInterface>& networkInterfaces, NetworkLogger& logger)
        : networkInterfaces(networkInterfaces), logger(logger) {
        std::lock_guard<std::mutex> lock(instanceMutex);
        instance = this;
    }

    // destructor
    PacketCollector::~PacketCollector()
    {
        if (isCapturing)
        {
            StopCapture();
        }
        else
        {
            std::cerr << "No packet capture operation at the moment\n";
        }
    }

    // function to check the number of connections to the same service
    int PacketCollector::countConnectionsToSameService(const Packet& currentConnection, std::vector<Connection>& connections, int numConnections)
    {       

        // Check if numConnections is less than or equal to zero
        if (numConnections <= 0) {
            logger.Log("Error: Invalid numConnections");
            return 0;  // or handle the error accordingly
        }
        
        // Check if connections vector is empty
        if (connections.empty()) {
            logger.Log("Error: Connections vector is empty");
            return 0;  // or handle the error accordingly
        }
        
        std::vector<Connection> connectionscpy = connections;
        
        // Initialize a counter for connections to the same service
        int connectionsToSameService = 0;
        
        // Parse the timestamp of the current connection
        std::tm currentTimestamp;
        std::istringstream timestampStream(currentConnection.timestamp);
        timestampStream >> std::get_time(&currentTimestamp, "%a %b %d %H:%M:%S %Y");
        
        // Check if parsing was successful
        if (!timestampStream.fail())
        {
            // Convert the current timestamp to a time_point
            auto currentConnectionTimePoint = std::chrono::system_clock::from_time_t(std::mktime(&currentTimestamp));
        
            // Calculate the timestamp for two seconds ago
            auto twoSecondsAgo = currentConnectionTimePoint - std::chrono::seconds(2);
        
            // Iterate through the connections array
            for (int i = 0; i < connectionscpy.size(); ++i)
            {
                // Parse the timestamp of the current array element
                std::tm arrayElementTimestamp;
                std::istringstream arrayElementTimestampStream(connectionscpy[i].timestamp);
                arrayElementTimestampStream >> std::get_time(&arrayElementTimestamp, "%a %b %d %H:%M:%S %Y");
        
                // Check if parsing was successful
                if (!arrayElementTimestampStream.fail())
                {
                    // Convert the array element timestamp to a time_point
                    auto arrayElementTimePoint = std::chrono::system_clock::from_time_t(std::mktime(&arrayElementTimestamp));
        
                    // Check if the connection occurred within the past two seconds
                    if (arrayElementTimePoint >= twoSecondsAgo && arrayElementTimePoint <= currentConnectionTimePoint)
                    {
                        // Check if the current connection has the same destination port as the current array element
                        if (connectionscpy[i].dport == currentConnection.dest_port)
                        {
                            // Increment the counter
                            connectionsToSameService++;
                        }
                    }
                }
                else
                {
                    // Handle parsing error for array element timestamp
                    logger.Log("Error parsing timestamp for array element " + std::to_string(i));
                    //std::cerr << "Error parsing timestamp for array element " << i << std::endl;
                }
            }
        }
        else
        {
            // Handle parsing error for current connection timestamp
            logger.Log("Error parsing timestamp for the current connection");
            //std::cerr << "Error parsing timestamp for the current connection" << std::endl;
        }
        
        return connectionsToSameService;
        
    }


    int PacketCollector::countConnectionsToSameDestination(const Packet& currentConnection, std::vector<Connection>& connections, int numConnections) 
    {

        in6_addr emptyIpv6;
        in_addr emptyIpv4;

        memset(&emptyIpv6, 0, sizeof(emptyIpv6)); // initialize to 0
        memset(&emptyIpv4, 0, sizeof(emptyIpv4)); // initialize to 0 

        // a copy of the array
        std::vector<Connection> connectionscpy = connections;

        // Initialize a counter for connections to the same service
        int connectionsToSameService = 0;

        // Check if the connections vector is not empty
        if (!connectionscpy.empty())
        {
            // Parse the timestamp of the current connection
            std::tm currentTimestamp;
            std::istringstream timestampStream(currentConnection.timestamp);
            timestampStream >> std::get_time(&currentTimestamp, "%a %b %d %H:%M:%S %Y");

            // Check if parsing was successful
            if (!timestampStream.fail())
            {
                // Convert the current timestamp to a time_point
                auto currentConnectionTimePoint = std::chrono::system_clock::from_time_t(std::mktime(&currentTimestamp));

                // Calculate the timestamp for two seconds ago
                auto twoSecondsAgo = currentConnectionTimePoint - std::chrono::seconds(2);

                // Iterate through the connections array
                for (int i = 0; i < connectionscpy.size(); ++i)
                {
                    // Parse the timestamp of the current array element
                    std::tm arrayElementTimestamp;
                    std::istringstream arrayElementTimestampStream(connectionscpy[i].timestamp);
                    arrayElementTimestampStream >> std::get_time(&arrayElementTimestamp, "%a %b %d %H:%M:%S %Y");

                    // Check if parsing was successful
                    if (!arrayElementTimestampStream.fail())
                    {
                        // Convert the array element timestamp to a time_point
                        auto arrayElementTimePoint = std::chrono::system_clock::from_time_t(std::mktime(&arrayElementTimestamp));

                        // Check if the connection occurred within the past two seconds
                        if (arrayElementTimePoint >= twoSecondsAgo && arrayElementTimePoint <= currentConnectionTimePoint)
                        {
                            // Check if the current connection has the same destination host as the current array element

                            if (memcmp(&connectionscpy[i].ip6_dst, &emptyIpv6, sizeof(in6_addr)) != 0 && memcmp(&currentConnection.ip6_dst, &emptyIpv6, sizeof(in6_addr)) != 0)
                            {
                                // Check if the current connection has the same destination port as the current array element
                                if (memcmp(&connectionscpy[i].ip6_dst, &currentConnection.ip6_dst, sizeof(in6_addr)) == 0)
                                {
                                    // Increment the counter
                                    connectionsToSameService++;
                                }
                            }
                            else
                            {
                                // Check if the current connection has the same destination port as the current array element
                                if (memcmp(&connectionscpy[i].ip_dst, &currentConnection.ip_dst, sizeof(in_addr)) != 0)
                                {
                                    // Increment the counter
                                    connectionsToSameService++;
                                }
                            }
                        }
                    }
                    else
                    {
                        // Handle parsing error for array element timestamp
                        logger.Log("Error parsing timestamp for array element " + std::to_string(i) + ": " + connections[i].timestamp);
                    }
                }
            }
            else
            {
                // Handle parsing error for current connection timestamp
                logger.Log("Error parsing timestamp for the current connection");
            }
        }
        else
        {
            // Handle the case where the connections vector is empty
            logger.Log("Connections vector is empty");
        }

        return connectionsToSameService;
       
    }

    int PacketCollector::CalculateConnectionTime(const std::vector<Connection>& connections, Packet packet)
    {
        // Function to convert timestamp strings to time_t
        auto convertTimestampToTime = [](const std::string& timestamp) {
            std::tm tm = {};
            std::istringstream timestampStream(timestamp);
            timestampStream >> std::get_time(&tm, "%a %b %d %H:%M:%S %Y");
            return  tm;
        };

        // Function to find the time difference between two timestamps in seconds
        auto getTimeDifference = [&convertTimestampToTime](const std::string& timestamp1, const std::string& timestamp2) {
            std::tm time1 = convertTimestampToTime(timestamp1);
            std::tm time2 = convertTimestampToTime(timestamp2);
            return std::difftime(std::mktime(&time2), std::mktime(&time1));
        };

        std::vector<Connection> matchingConnections;

        // Find all connections with the same port as the target port
        for (const auto& connection : connections) 
        {
            if (connection.dport == packet.dest_port) 
            {
                matchingConnections.push_back(connection);
            }
        }

        if (matchingConnections.empty()) 
        {
            std::cerr << "No connections found with port " << packet.dest_port << std::endl;
            return 0.0;
        }

        // Find the connection with the highest timestamp
        auto maxTimestampConnection = std::max_element(matchingConnections.begin(), matchingConnections.end(), [](const Connection& a, const Connection& b) {
            return a.timestamp < b.timestamp;
            });

        // Find the connection with the smallest timestamp
        auto minTimestampConnection = std::min_element(matchingConnections.begin(), matchingConnections.end(), [](const Connection& a, const Connection& b) {
            return a.timestamp < b.timestamp;
            });

        double timeDifference = getTimeDifference(minTimestampConnection->timestamp, maxTimestampConnection->timestamp);

        return timeDifference;
    }

    Datapoint PacketCollector::AttributeExtractor(const u_char* packetData, Packet packet, const struct pcap_pkthdr& header, const IP* ipHeader, int connectionTime, int headerSize, uint8_t ipHeaderLength, uint16_t srcBytes, uint16_t dstBytes)
    {
         Datapoint datapoint;
        // store the connection in the connection table
        Connection connection;        

        // Extract IP header fields
        datapoint.duration = CalculateConnectionTime(connectionsTable, packet);

        if (packet.protocol_type.empty())
        {
            packet.protocol_type = "other";
        }

        datapoint.protocol_type = packet.protocol_type;

        // determining the service
        if (datapoint.protocol_type == "tcp")
        {
            // Extract the destination port from the TCP header
            uint16_t destPort = packet.dest_port;

            // Determine the service based on the destination port
            switch (destPort)
            {
            case 80:
                datapoint.service = "http";
                break;
            case 443:
                datapoint.service = "https";
                break;
            case 21:
                datapoint.service = "ftp";
                break;
            case 25:
                datapoint.service = "smtp";
                break;
            case 110:
                datapoint.service = "pop3";
                break;
            case 23:
                datapoint.service = "telnet";
                break;
            case 143:
                datapoint.service = "imap4";
                break;
            case 22:
                datapoint.service = "ssh";
                break;
            case 105:
                datapoint.service = "csnet_s";
                break;
            case 11:
                datapoint.service = "systat";
                break;
            case 106:
                datapoint.service = "eco_i";
                break;
            case 389:
                datapoint.service = "idap";
                break;
            case 540:
                datapoint.service = "uucp";
                break;
            case 43:
                datapoint.service = "whois";
                break;
            default:
                datapoint.service = "other";
            }

        }
        else if (datapoint.protocol_type == "udp")
        {
            // Extract the destination port from the UDP header
            uint16_t destPort = packet.dest_port;

            // Determine the service based on the destination port
            switch (destPort)
            {
            case 53:
                datapoint.service = "domain_u";
                break;
            case 67:
            case 68:
                datapoint.service = "dhcp";
                break;
            case 123:
                datapoint.service = "ntp";
                break;
            case 161:
                datapoint.service = "snmp";
                break;
            case 137:
                datapoint.service = "netbios";
                break;
                break;
            default:
                datapoint.service = "other";
            }
        }
        else if (datapoint.protocol_type == "icmp")
        {
            // ICMP doesn't have ports, so determining the service might be based on specific ICMP message types
            const u_char* icmpHeader = packetData + headerSize + ipHeaderLength;

            // Extract the ICMP type
            uint8_t icmpType = (icmpHeader != nullptr) ? icmpHeader[0] : 0;

            // Determine the service based on the ICMP type
            switch (icmpType)
            {
            case 1:
                datapoint.service = "ecr_i";
                break;
            default:
                datapoint.service = "other";
            }
        }
        else
        {
            datapoint.service = "other";
        }

        // Flags
        if (datapoint.protocol_type == "tcp")
        {
            const u_char* tcpHeader = reinterpret_cast<const u_char*>(ipHeader) + headerSize + ipHeaderLength; // Offset for the start of the TCP header
            uint16_t tcpFlags = ntohs(*reinterpret_cast<const uint16_t*>(tcpHeader + 12)); // Offset for TCP flags (12 bytes into the header)

            // Check the TCP flags to determine the active flag
            if (tcpFlags & 0x01)
            {
                datapoint.flag = "FIN";
            }
            else if (tcpFlags & 0x02)
            {
                datapoint.flag = "SYN";
            }
            else if (tcpFlags & 0x04)
            {
                datapoint.flag = "RST";
            }
            else if (tcpFlags & 0x08)
            {
                datapoint.flag = "PUSH";
            }
            else if (tcpFlags & 0x10)
            {
                datapoint.flag = "ACK";
            }
            else if (tcpFlags & 0x20)
            {
                datapoint.flag = "URG";
            }
            else if (tcpFlags & 0x40)
            {
                datapoint.flag = "ECE";
            }
            else if (tcpFlags & 0x80)
            {
                datapoint.flag = "CWR";
            }
            else
            {
                datapoint.flag = "other"; // If no active flag is set
            }

            // Additional logic for specific flags
            if (tcpFlags & 0x04 && tcpFlags & 0x10)
            {
                datapoint.flag = "RSTO"; // Reset connection because of RST and ACK flags
                connection.flags = reinterpret_cast<u_char>("RSTO");
            }
            else if (tcpFlags & 0x04 && !(tcpFlags & 0x10))
            {
                datapoint.flag = "RSTR"; // Reset connection without ACK flag
                connection.flags = reinterpret_cast < u_char>("RSTR");
            }
            else if (tcpFlags & 0x08 && !(tcpFlags & 0x02))
            {
                datapoint.flag = "REJ"; // Reject connection without SYN flag
                connection.flags = reinterpret_cast < u_char>("REJ");
            }
            else if (tcpFlags & 0x02 && tcpFlags & 0x10)
            {
                datapoint.flag = "SF"; // Successful connection because of SYN and ACK flags
                connection.flags = reinterpret_cast < u_char>("SF");
            }
            else if (tcpFlags & 0x02 && !(tcpFlags & 0x10))
            {
                datapoint.flag = "SO"; // Open connection without ACK flag
                connection.flags = reinterpret_cast < u_char>("SO");
            }

        }
        else if (datapoint.protocol_type == "udp")
        {
            datapoint.flag = "N/A"; // no flags in UDP
        }
        else if (datapoint.protocol_type == "icmp")
        {
            const u_char* icmpHeader = reinterpret_cast<const u_char*>(ipHeader) + ipHeaderLength; // Offset for the start of the ICMP header
            uint8_t icmpType = (icmpHeader != nullptr) ? icmpHeader[0] : 0;

            // Check the ICMP type to determine the active flag
            switch (icmpType) {
            case 0:
                datapoint.flag = "Echo Reply";
                connection.flags = reinterpret_cast < u_char>("Echo Reply");
                break;
            case 3:
                datapoint.flag = "Destination Unreachable";
                connection.flags = reinterpret_cast < u_char>("Destination Unreachable");
                break;
            case 8:
                datapoint.flag = "Echo Request";
                connection.flags = reinterpret_cast < u_char>("Echo Request");
                break;
            default:
                datapoint.flag = "other";
                connection.flags = reinterpret_cast < u_char>("other");
            }
        }
        else
        {
            datapoint.flag = "other"; // Handle other transport layer protocols
            connection.flags = reinterpret_cast < u_char>("other");
        }

        in6_addr emptyipv6;
        in_addr emptyipv4;

        memset(&emptyipv6, 0, sizeof(in6_addr));
        memset(&emptyipv4, 0, sizeof(in_addr));

        if (memcmp(&packet.ip6_src, &emptyipv6, sizeof(in6_addr)) != 0)
        {
            connection.ip6_src = packet.ip6_src;
            connection.ip6_dst = packet.ip6_dst;
        }
        else
        {
            connection.ip_src = packet.ip_src;
            connection.ip_dst = packet.ip_dst;
        }        

        connection.sport = packet.source_port;
        connection.dport = packet.dest_port;

        datapoint.src_bytes = srcBytes;
        datapoint.dst_bytes = dstBytes;


        if(memcmp(&packet.ip_src, &emptyipv4, sizeof(in_addr)) != 0 && memcmp(&packet.ip_dst, &emptyipv4, sizeof(in_addr)) != 0)
            datapoint.land = (memcmp(&packet.ip_src, &packet.ip_dst, sizeof(in_addr)) == 0 && packet.source_port == packet.dest_port) ? 1 : 0;
        else if (memcmp(&packet.ip6_src, &emptyipv6, sizeof(in6_addr)) != 0 && memcmp(&packet.ip6_dst, &emptyipv6, sizeof(in6_addr)) != 0)
            datapoint.land = (memcmp(&packet.ip6_src, &packet.ip6_dst, sizeof(in6_addr)) == 0 && packet.source_port == packet.dest_port) ? 1 : 0;


        // extracting wrong fragments 
        if (datapoint.protocol_type == "tcp")
        {
            const u_char* tcpHeader = packetData + headerSize + ipHeaderLength;

            // Extract the TCP flags field (byte 13 of the TCP header)
            uint8_t tcpFlags = (tcpHeader != nullptr) ? tcpHeader[13] : 0;

            // Check if the URG (urgent) and DF (don't fragment) flags are set
            bool urgentFlagSet = (tcpFlags & 0x20) != 0;
            bool dfFlagSet = (tcpFlags & 0x40) != 0;

            // Count the number of wrong fragments based on the DF flag
            int wrongFragmentCount = dfFlagSet ? 1 : 0;

            // Count the number of urgent packets based on the URG flag
            int urgentPacketCount = urgentFlagSet ? 1 : 0;

            datapoint.wrong_fragment = wrongFragmentCount;
            datapoint.urgent = urgentPacketCount;
        }
        else if (datapoint.protocol_type == "udp")
        {
            // Extract the source and destination ports from the UDP header
            uint16_t sourcePort = packet.source_port;
            uint16_t destinationPort = packet.dest_port;

            //conditions for "Wrong_fragment" and "Urgent" in UDP
            bool wrongFragmentCondition = (sourcePort == 12345 && destinationPort == 54321);
            bool urgentCondition = (sourcePort == 54321 && destinationPort == 12345);

            // Count the number of wrong fragments and urgent packets based on the conditions
            int wrongFragmentCount = wrongFragmentCondition ? 1 : 0;
            int urgentPacketCount = urgentCondition ? 1 : 0;

            datapoint.wrong_fragment = wrongFragmentCount;
            datapoint.urgent = urgentPacketCount;
        }
        else if (datapoint.protocol_type == "icmp")
        {
            const u_char* icmpHeader = packetData + headerSize + ipHeaderLength;

            // Extract the ICMP type and code
            uint8_t icmpType = (icmpHeader != nullptr) ? icmpHeader[0] : 0;
            uint8_t icmpCode = (icmpHeader != nullptr) ? icmpHeader[1] : 0;

            // Example conditions for ICMP (adjust as needed)
            bool wrongFragmentCondition = (icmpType == 3 && icmpCode == 4); // Example: ICMP Destination Unreachable, Fragmentation Needed
            bool urgentCondition = (icmpType == 8 && icmpCode == 0); // Example: ICMP Echo Request (Ping)

            // Count the number of packets meeting the conditions
            int wrongFragmentCount = wrongFragmentCondition ? 1 : 0;
            int urgentPacketCount = urgentCondition ? 1 : 0;

            datapoint.wrong_fragment = wrongFragmentCount;
            datapoint.urgent = urgentPacketCount;
        }
        else
        {
            logger.Log("Unknown fragment or urgent flag");
            //std::cerr << "Unknown fragment or urgent flag"<< std::endl;
        }

        // Assuming payload follows the IP header
        const u_char* payload = packet.payload;

        // Calculate the payload length
        uint16_t payloadLength = header.caplen - headerSize - ipHeaderLength; // Skip Ethernet + IP header

        // Check if the payload is valid
        if (payloadLength > 0 && payload != nullptr)
        {
            try
            {
                // Extract the payload
                std::string payloadString(reinterpret_cast<const char*>(payload), payloadLength);

                // Check for specific payload content
                if (payloadString.find("ENTER_SYSTEM_DIRECTORY") != std::string::npos)
                {
                    datapoint.hot = 1;
                }
                else
                {
                    datapoint.hot = 0;
                }                

                // Check for additional conditions based on service type
                if (datapoint.service == "ssh" || datapoint.service == "telnet" || datapoint.service == "ftp")
                {
                    for (const auto& connection : connectionsTable)
                    {
                        if (connection.dport == packet.dest_port || connection.sport == packet.source_port)
                        {
                            // Check for failed login attempts
                            if (connection.payloadString == "Failed password" && payloadString.find("Failed password") != std::string::npos)
                            {
                                datapoint.num_failed_logins++;
                            }

                            // Check for compromised conditions (example: detecting suspicious commands)
                            if (connection.payloadString == "rm -rf /" && payloadString.find("rm -rf /") != std::string::npos)
                            {
                                datapoint.num_compromised++;
                            }

                            // Check for root accesses
                            if (connection.payloadString == "root access" && payloadString.find("root access") != std::string::npos)
                            {
                                datapoint.num_root++;
                            }

                            // Check for file creations
                            if (connection.payloadString == "STOR" && payloadString.find("STOR ") != std::string::npos)
                            {
                                datapoint.num_file_creations++;
                            }

                            // Check for shell prompts
                            if (connection.payloadString == "sh" && payloadString.find("sh") != std::string::npos)
                            {
                                datapoint.num_shells++;
                            }

                            // Check for operations on access control files
                            if (connection.payloadString == "chmod" && payloadString.find("chmod") != std::string::npos || payloadString.find("chown") != std::string::npos)
                            {
                                datapoint.num_access_files++;
                            }

                            // Check for outbound commands in an FTP session
                            if (connection.payloadString == "PORT" && payloadString.find("PORT") != std::string::npos || payloadString.find("PASV") != std::string::npos)
                            {
                                datapoint.num_outbound_cmds++;
                            }
                        }
                    }                    

                    // Check for successful login
                    if (payloadString.find("Accepted password") != std::string::npos)
                    {
                        datapoint.logged_in = 1;
                    }                    

                    // Check for root shell
                    if (payloadString.find("root shell") != std::string::npos)
                    {
                        datapoint.root_shell = 1;
                    }

                    // Check for su command attempts
                    if (payloadString.find("su ") != std::string::npos)
                    {
                        datapoint.su_attempted = 1;
                    }                  

                    // Check for hot login (example: detecting root or admin logins)
                    if (payloadString.find("root") != std::string::npos || payloadString.find("admin") != std::string::npos)
                    {
                        datapoint.is_host_login = 1;
                    }

                    // Check for guest login
                    if (payloadString.find("guest") != std::string::npos)
                    {
                        datapoint.is_guest_login = 1;
                    }
                }
                // update connection payload string
                connection.payloadString = payloadString;
            }
            catch (const std::exception& e)
            {
                // Handle the exception (e.g., invalid memory access)
                logger.Log("Error reading payload memory: " +  std::string(e.what()));
                //std::cerr << "Error reading payload memory: " << e.what() << std::endl;
            }
        }
        else
        {
            logger.Log("Invalid payload");
            //std::cerr << "Invalid payload" << std::endl;
        }

        // connections to the same destination host as the current connection in thre past two seconds
        std::lock_guard<std::mutex> readLock(connectionsMutex);
        int count = countConnectionsToSameDestination(packet, connectionsTable, connectionsTable.size());

        std::lock_guard<std::mutex> readLock1(connectionsMutex1);
        int srv_count = countConnectionsToSameService(packet, connectionsTable, connectionsTable.size());

        datapoint.count = count;
        datapoint.srv_count = srv_count;        

        connection.timestamp = packet.timestamp;

        int serror = 0;
        int rerror = 0;
        int same_srv = 0; // same service
        int diff_srv = 0; // different services
        int diff_dest = 0; // different destinations
        int samedsthostno = 0; //same destination host
        int sameportno = 0; // connections with same port
        int samesourceport = 0; // same source port
        int totalConnections = 0;

        // Iterate through the connectionTable vector
        for (const auto& connection : connectionsTable)
        {
            // Increment totalConnections
            totalConnections++;
            in6_addr emptyipv6;
            in_addr emptyipv4;

            memset(&emptyipv6, 0, sizeof(in6_addr));
            memset(&emptyipv4, 0, sizeof(in_addr));

            if (connection.dport == packet.dest_port)
            {
                if (connection.flags == reinterpret_cast <u_char>("SF") || connection.flags == reinterpret_cast <u_char>("SO"))
                {
                    serror++;
                }

                if (connection.flags == reinterpret_cast<u_char>("REJ"))
                {
                    rerror++;
                }

                if (connection.dport == packet.dest_port)
                {
                    same_srv++;
                }

                if (memcmp(&connection.ip6_dst, &emptyipv6, sizeof(in6_addr)) != 0 && memcmp(&packet.ip6_dst, &emptyipv6, sizeof(in6_addr)) != 0)
                {
                    if (memcmp(&connection.ip6_dst, &packet.ip6_dst, sizeof(in6_addr)) != 0)
                    {
                        diff_dest++;
                    }
                    else if (memcmp(&connection.ip6_dst, &packet.ip6_dst, sizeof(in6_addr)) == 0)
                    {
                        samedsthostno++;
                    }
                }
                else
                {
                    if (memcmp(&connection.ip_dst, &packet.ip_dst, sizeof(in_addr))  != 0)
                    {
                        diff_dest++;
                    }
                    else if (memcmp(&connection.ip_dst, &packet.ip_dst, sizeof(in_addr)) == 0)
                    {
                        samedsthostno++;
                    }
                }

                if (connection.sport == packet.source_port && connection.dport == packet.dest_port)
                {
                    sameportno++;
                }

                if (connection.sport == packet.source_port)
                {
                    samesourceport++;
                }
                
            }
            else
            {
                diff_srv++;
            }
            
        }

        if (count != 0)
        {
            datapoint.serror_rate = std::round((static_cast<double>(serror) / count) * 100.0) / 100.0;
            datapoint.rerror_rate = std::round((static_cast<double>(rerror) / count) * 100.0) / 100.0;
            datapoint.same_srv_rate = std::round((static_cast<double>(same_srv) / count) * 100.0) / 100.0;
            datapoint.diff_srv_rate = std::round((static_cast<double>(diff_srv) / count) * 100.0) / 100.0;
        }

        if (srv_count != 0)
        {
            datapoint.srv_serror_rate = std::round((static_cast<double>(serror) / srv_count) * 100.0) / 100.0;
            datapoint.srv_rerror_rate = std::round((static_cast<double>(rerror) / srv_count) * 100.0) / 100.0;
            datapoint.srv_diff_host_rate = std::round((static_cast<double>(diff_dest) / srv_count) * 100.0) / 100.0;
        }

        datapoint.dst_host_count = samedsthostno;

        if (samedsthostno != 0)
        {
            datapoint.dst_host_same_srv_rate = std::round((static_cast<double>(srv_count) / samedsthostno) * 100.0) / 100.0;
            datapoint.dst_host_diff_srv_rate = std::round((static_cast<double>(diff_srv) / samedsthostno) * 100.0) / 100.0;
        }

        if (samesourceport != 0)
        {
            datapoint.dst_host_same_src_port_rate = std::round((static_cast<double>(sameportno) / samesourceport) * 100.0) / 100.0;
        }

        if (sameportno != 0)
        {
            datapoint.dst_host_srv_diff_host_rate = std::round((static_cast<double>(diff_dest) / sameportno) * 100.0) / 100.0;
            datapoint.dst_host_srv_serror_rate = std::round((static_cast<double>(serror) / sameportno) * 100.0) / 100.0;
            datapoint.dst_host_srv_rerror_rate = std::round((static_cast<double>(rerror) / sameportno) * 100.0) / 100.0;
        }

        if (samedsthostno != 0)
        {
            datapoint.dst_host_serror_rate = std::round((static_cast<double>(serror) / samedsthostno) * 100.0) / 100.0;
            datapoint.dst_host_rerror_rate = std::round((static_cast<double>(rerror) / samedsthostno) * 100.0) / 100.0;
        }

        std::lock_guard<std::mutex> lock(connTable);
        connectionsTable.push_back(connection);

        std::lock_guard<std::mutex> lock1(datapointMutex);
        datapoints.push_back(datapoint);

        std::shared_ptr<PacketAnalyzer::KNN> knn = std::make_shared<PacketAnalyzer::KNN>(3);
        std::shared_ptr<DataCollection::DataHandler> dh = std::make_shared<DataCollection::DataHandler>();       

        
        {
            std::lock_guard<std::mutex> lock2(inspectMutex);
            std::string fileName = "CSMLM.dat";
            try
            {
                knn->LoadKNN(fileName);
                std::cout << "Model Loaded successfully!" << std::endl;
                knn->InspectDataPoint(dh->CreateDataInstance(datapoint.toCSVString()));
            }
            catch (const std::exception e)
            {
                std::cerr << "Error loading model: " << e.what() << std::endl;
            }
            
        }
        

        return datapoint;
    }

    std::vector<Datapoint> PacketCollector::GetDatapoints()
    {
        return datapoints;
    }

    // signal handler
    void PacketCollector::SignalHandler(int signal)
    {
        // Handle interrupt signal (Ctrl + C) to stop packet capture
        std::cout << "Cleaning up and exiting..." << std::endl;
        g_programShouldExit = 1;
    }

    // call the non-static SignalHandler through an instance
    void PacketCollector::StaticSignalHandler(int signal)
    {
        instance->SignalHandler(signal);
    }

    // Start packet capture method
    void PacketCollector::StartCapture()
    {
        {
            // Ensure that only one thread can enter this method at a time
            std::lock_guard<std::mutex> lock(instanceMutex);

            // register the signal handler function to handle the keyboard interrupt
            std::signal(SIGINT, &StaticSignalHandler);

            // Check if packet capturing is in progress
            if (isCapturing.load(std::memory_order_relaxed))
            {
                logger.Log("Already capturing\n");
                //std::cerr << "Already capturing\n" << std::endl;
                return;
            }

            // Initialize the barrier to ensure all threads start capturing together
            startBarrier.store(0, std::memory_order_relaxed);

            // Start a capture thread for each network interface
            for (auto& iface : networkInterfaces)
            {
                threads.emplace_back([this, &iface] { CapturePackets(iface); });
                startBarrier.fetch_add(1, std::memory_order_relaxed); // Increment the barrier count
            }
        }

        // Wait for all threads to be ready to capture
        std::unique_lock<std::mutex> startLock(startMutex);
        startCV.wait(startLock, [this] {
            return startBarrier.load(std::memory_order_relaxed) == networkInterfaces.size();
            });

        // Set a flag to indicate that capturing is in progress
        isCapturing.store(true, std::memory_order_relaxed);
    }

    // packet capturing logic
    void PacketCollector::CapturePackets(const NetworkInterface& iface)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcapHandle = nullptr;

        // Open the interface and store the handle in the local variable
        pcapHandle = pcap_open_live(iface.interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);

        if (pcapHandle == nullptr) {
            std::string errorMsg = "Error: Failed to open network interface (" + iface.interfaceName + "): " + errbuf;
            logger.Log(errorMsg);
            std::cerr << errorMsg << std::endl;

            pcap_close(pcapHandle);
            startBarrier.fetch_sub(1, std::memory_order_relaxed); // Release the thread from the barrier
            return;
        }

        // Capture start time
        std::chrono::system_clock::time_point captureStartTime = std::chrono::system_clock::now();
        
        while (isCapturing.load(std::memory_order_relaxed))
        {
            struct pcap_pkthdr header;
            const u_char* packetData = pcap_next(pcapHandle, &header);

            if (packetData != nullptr)
            {
                ProcessPacket(packetData, header, iface, captureStartTime);
            }
        }

        pcap_close(pcapHandle);

        // Decrease the startBarrier count when capturing is done
        startBarrier.fetch_sub(1, std::memory_order_relaxed);

        // Lock and store the captured packets in the map
        {
            std::lock_guard<std::mutex> lock(capturedPacketsMutex);
            capturedPackets[iface.interfaceName] = capturedPacketsArr;
        }
    }

    // Process the packet collected
    void PacketCollector::ProcessPacket(const u_char* packetData, const struct pcap_pkthdr& header, const NetworkInterface& iface, std::chrono::system_clock::time_point captureStartTime)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(iface.interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);

        int linkType = pcap_datalink(handle);  // determine the link layer protocol

        // get the timestamp from when the packet was captured
        std::chrono::system_clock::time_point timestamp = std::chrono::system_clock::from_time_t(header.ts.tv_sec);
        timestamp += std::chrono::microseconds(header.ts.tv_sec);

        // calculate the connection time
        std::chrono::duration<double> connectionTime = timestamp - captureStartTime;

        // convert connection time to seconds
        int connectionTimeInSeconds = connectionTime.count();

        Packet packet;

        // Buffer to store the formatted timestamp
        char timestampBuffer[26];
        time_t timestamp1 = header.ts.tv_sec;

        if (timestamp1 > 0)
        {
            // Ensure timestampBuffer is large enough to hold the formatted timestamp
            if (ctime_s(timestampBuffer, sizeof(timestampBuffer), &timestamp1) == 0)
            {
                packet.timestamp = timestampBuffer;
            }
            else
            {
                // Handle the error from ctime_s
                packet.timestamp = "Error formatting timestamp";
            }
        }
        else
        {
            // Handle the case where timestamp is not a valid time_t value
            packet.timestamp = "Invalid timestamp value";
        }

        int headerSize = 0;
        uint8_t ipHeaderLength = 0;
        const IP* ipHeader = nullptr;
        uint16_t srcBytes = 0;
        uint16_t dstBytes = 0;

        packet.payload = nullptr;

        if (handle != nullptr)
        {
            if (linkType == LinkType::ETHERNETFRAME) // link layer protocol is ethernet
            {
                // identify ip versions
                const uint16_t ethType = (packetData[12] << 8) | packetData[13];

                headerSize = ETHERNETHEADERSIZE;

                // Extract Ethernet header
                const struct EATHERNET_HEADER* ethernetHeader = (struct EATHERNET_HEADER*)packetData;

                if (ethType == 0x0800) // ipv4 ethernet frame
                {

                    // Extract ipv4 header information
                    ipHeader = reinterpret_cast<const IP*>(packetData + headerSize);
                    uint8_t ipVersion = (packetData[14] >> 4) & 0x0F;
                    ipHeaderLength = (packetData[14] & 0x0F) * 4;

                    // Extract protocol type
                    uint8_t protocolType = ipHeader->ip_p;

                    // Extract source and destination bytes
                    srcBytes = ntohs(ipHeader->ip_src.S_un.S_un_w.s_w1);
                    dstBytes = ntohs(ipHeader->ip_dst.S_un.S_un_w.s_w1);

                    // Extract the flags, payload, source port and destination port
                    if (protocolType == IPPROTO_TCP)
                    {
                        packet.protocol_type = "tcp";
                        // Extract TCP header information
                        const TCP* tcpHeader = reinterpret_cast<const TCP*>(reinterpret_cast<const UCHAR*>(ipHeader) + ipHeaderLength);
                        uint8_t tcpHeaderLength = TH_OFF(tcpHeader) * 4; // in bytes
                        packet.source_port = ntohs(tcpHeader->th_sport);
                        packet.dest_port = ntohs(tcpHeader->th_dport);

                        // Extract the TCP flag
                        packet.flags = tcpHeader->th_flags;

                        // Extract payload
                        packet.payload = packetData + headerSize + ipHeaderLength + tcpHeaderLength;
                    }
                    else if (protocolType == IPPROTO_UDP)
                    {
                        packet.protocol_type = "udp";

                        const UDP* udpHeader = reinterpret_cast<const UDP*>(reinterpret_cast<const UCHAR*>(ipHeader) + ipHeaderLength);
                        
                        // Extract UDP header information
                        packet.source_port = ntohs(udpHeader->source_port);
                        packet.dest_port = ntohs(udpHeader->dest_port);
                        uint16_t udpLength = ntohs(udpHeader->length);

                        packet.payload = packetData + headerSize + ipHeaderLength + sizeof(UDP);
                    }
                    else if (protocolType == IPPROTO_ICMP)
                    {
                        packet.protocol_type = "icmp";

                        const ICMP* icmpHeader = reinterpret_cast<const ICMP*>(reinterpret_cast<const UCHAR*>(ipHeader) + ipHeaderLength);
                        // Extract ICMP header information
                        uint8_t icmpType = icmpHeader->type;
                        uint8_t icmpCode = icmpHeader->code;

                        // ICMP does not have ports, so no need to extract source and destination ports

                         // Flag-like logic based on ICMP Type (You can process the messages further to determine the flag returned)
                        bool isEchoRequest = (icmpType == 8);  // ICMP Echo Request
                        bool isEchoReply = (icmpType == 0);    // ICMP Echo Reply

                        // Extract payload
                        packet.payload = packetData + headerSize + ipHeaderLength + sizeof(ICMP); // ICMP header is typically 8 bytes
                    }
                    else
                    {
                        packet.protocol_type = "other";
                        logger.Log("Invalid protocol");
                        //std::cerr << "Invalid protocol"<< std::endl;
                    }

                    packet.ip_ttl = ipHeader->ip_ttl;

                    packet.ip_src = ipHeader->ip_src;
                    packet.ip_dst = ipHeader->ip_dst;

                }
                else if (ethType == 0x86DD) // ipv6 ethernet frame
                {
                    size_t ipv6HeaderSize = 40; // IPv6 header size is fixed at 40 bytes

                    // Extract IPv6 header information
                    const IPV6_HEADER* ipv6Header = reinterpret_cast<const IPV6_HEADER*>(packetData + headerSize);

                    uint8_t payloadLength = ntohs(ipv6Header->payloadLength);
                    uint8_t nextHeader = ipv6Header->nextHeader; // Protocol type following IPv6 header
                    uint8_t hopLimit = ipv6Header->hopLimit; //ttl

                    packet.ip_ttl = hopLimit;

                    // Extract source and destination IPv6 addresses
                    packet.ip6_src = ipv6Header->sourceIPv6;
                    packet.ip6_dst = ipv6Header->destIPv6;

                    // Extract source and destination bytes
                    srcBytes = (packetData[22] << 8) | packetData[23];
                    dstBytes = (packetData[38] << 8) | packetData[39];

                    // Extract the flags, payload, source port, and destination port (if applicable)
                    if (nextHeader == IPPROTO_TCP)
                    {
                        packet.protocol_type = "tcp";

                        const TCP* tcpHeader = reinterpret_cast<const TCP*>(packetData + headerSize + ipv6HeaderSize);

                        // Extract TCP header information
                        uint8_t tcpHeaderLength = TH_OFF(tcpHeader) * 4; // in bytes

                        packet.source_port = ntohs(tcpHeader->th_sport);
                        packet.dest_port = ntohs(tcpHeader->th_dport);

                        // Extract the TCP flag
                        packet.flags = tcpHeader->th_flags;

                        // Extract payload
                        packet.payload = packetData + headerSize + ipv6HeaderSize + tcpHeaderLength; // Adjust the offset based on the actual header lengths
                    }
                    else if (nextHeader == IPPROTO_UDP)
                    {
                        packet.protocol_type = "udp";

                        const UDP* udpHeader = reinterpret_cast<const UDP*>(packetData + headerSize + ipv6HeaderSize);

                        // Extract UDP header information
                        packet.source_port = ntohs(udpHeader->source_port);
                        packet.dest_port = ntohs(udpHeader->dest_port);
                        uint16_t udpLength = ntohs(udpHeader->length);

                        packet.payload = packetData + headerSize + ipv6HeaderSize + sizeof(UDP); // Adjust the offset based on the actual header lengths
                    }
                    else if (nextHeader == IPPROTO_ICMPV6)
                    {
                        packet.protocol_type = "icmp";

                        const ICMP* icmpv6Header = reinterpret_cast<const ICMP*>(packetData + headerSize + ipv6HeaderSize);

                        // Extract ICMPv6 header information
                        uint8_t icmpType = icmpv6Header->type;
                        uint8_t icmpCode = icmpv6Header->code;

                        // ICMPv6 does not have ports, so no need to extract source and destination ports

                        // Flag-like logic based on ICMPv6 Type
                        // (You can process the messages further to determine the flag returned)
                        bool isEchoRequest = (icmpType == 128);  // ICMPv6 Echo Request
                        bool isEchoReply = (icmpType == 129);    // ICMPv6 Echo Reply

                        packet.payload = packetData + headerSize + ipv6HeaderSize + sizeof(ICMP); // Adjust the offset based on the actual header lengths
                    }
                    else
                    {
                        packet.protocol_type = "other";
                        logger.Log("Invalid protocol");
                        //std::cerr << "Invalid protocol" << std::endl;
                    }

                }
                else
                {
                    logger.Log("Unknown version");
                    //std::cerr << "Unknown version" << std::endl;
                }
            }
            else if (linkType == LinkType::WIFIFRAME)
            {
                // Identify IP versions
                const uint16_t ethType = (packetData[30] << 8) | packetData[31]; // Assuming Ethernet II frame

                headerSize = WIFIHEADERSIZE;

                if (ethType == 0x0800)
                { // IPv4 ethertype
                    // Check if there is a Radiotap header
                    uint8_t radiotapHeaderLength = 0;
                    if (header.caplen >= 3)
                    {
                        radiotapHeaderLength = packetData[2];
                    }

                    // Check if IEEE 802.11 header follows the Radiotap header
                    uint8_t ieee80211FrameOffset = radiotapHeaderLength;

                    // Assuming ieee80211FrameOffset is the offset to the beginning of the IEEE 802.11 header
                    uint16_t frameControlField = (packetData[ieee80211FrameOffset + 1] << 8) | packetData[ieee80211FrameOffset];

                    // Assuming the data frame control field is 2 bytes
                    uint16_t dataFrameControlField = (packetData[ieee80211FrameOffset + 24 + 1] << 8) | packetData[ieee80211FrameOffset + 24];

                    // Extract IEEE 802.11 header information
                    uint8_t frameType = (dataFrameControlField & 0x0C) >> 2;  // Extract frame control type bits
                    uint8_t frameSubtype = (dataFrameControlField & 0xF0) >> 4; // Extract frame subtype bits

                    // Define header size based on frame type and subtype
                    uint8_t ieee80211HeaderSize = 24; // Common header size

                    if (frameType == 0x00 && frameSubtype == 0x08)
                    {
                        // Management frame subtype 0x08 (Beacon frame) example
                        // Beacon frames have a fixed size of 24 bytes for the management header
                        ieee80211HeaderSize = 24;
                    }
                    else if (frameType == 0x02)
                    {
                        // Data frame example
                        ieee80211HeaderSize += 2;
                    }

                    // Assuming the presence of an IP payload (e.g., IPv4)
                    uint8_t ipHeaderOffset = ieee80211FrameOffset + ieee80211HeaderSize;

                    // Extract IP header information
                    uint8_t ipVersion = (packetData[ipHeaderOffset] >> 4) & 0x0F;
                    uint8_t ipHeaderLength = (packetData[ipHeaderOffset] & 0x0F) * 4;

                    // Extract protocol type
                    uint8_t protocolType = packetData[ipHeaderOffset + 9]; // TCP/UDP/ICMP

                    // Extract common information
                    packet.ip_ttl = packetData[ipHeaderOffset + 8];
                    packet.ip_src.S_un.S_addr = *reinterpret_cast<const uint32_t*>(&packetData[ipHeaderOffset + 12]);
                    packet.ip_dst.S_un.S_addr = *reinterpret_cast<const uint32_t*>(&packetData[ipHeaderOffset + 16]);

                    // Extract source and destination bytes
                    uint16_t srcBytes = (packetData[ipHeaderOffset + 12] << 8) | packetData[ipHeaderOffset + 13];
                    uint16_t dstBytes = (packetData[ipHeaderOffset + 14] << 8) | packetData[ipHeaderOffset + 15];

                    // Handle specific protocols
                    if (protocolType == IPPROTO_TCP)
                    {
                        packet.protocol_type = "tcp";
                        // Extract TCP header information
                        uint8_t tcpHeaderLength = ((packetData[ipHeaderOffset + 12] >> 4) & 0x0F) * 4; // in bytes
                        packet.source_port = (packetData[ipHeaderOffset + tcpHeaderLength] << 8) | packetData[ipHeaderOffset + tcpHeaderLength + 1];
                        packet.dest_port = (packetData[ipHeaderOffset + tcpHeaderLength + 2] << 8) | packetData[ipHeaderOffset + tcpHeaderLength + 3];

                        // Extract the TCP flag
                        packet.flags = packetData[ipHeaderOffset + tcpHeaderLength + 13];

                        // Extract payload
                        packet.payload = packetData + ipHeaderOffset + tcpHeaderLength;
                    }
                    else if (protocolType == IPPROTO_UDP)
                    {
                        packet.protocol_type = "udp";
                        // Extract UDP header information
                        packet.source_port = (packetData[ipHeaderOffset] << 8) | packetData[ipHeaderOffset + 1];
                        packet.dest_port = (packetData[ipHeaderOffset + 2] << 8) | packetData[ipHeaderOffset + 3];
                        uint16_t udpLength = (packetData[ipHeaderOffset + 4] << 8) | packetData[ipHeaderOffset + 5];

                        // No flags for UDP

                        // Extract payload
                        packet.payload = packetData + ipHeaderOffset + udpLength;
                    }
                    else if (protocolType == IPPROTO_ICMP)
                    {
                        packet.protocol_type = "icmp";
                        // Extract ICMP header information
                        uint8_t icmpType = packetData[ipHeaderOffset];
                        uint8_t icmpCode = packetData[ipHeaderOffset + 1];

                        // ICMP does not have ports, so no need to extract source and destination ports

                        // Flag-like logic based on ICMP Type (You can process the messages further to determine the flag returned)
                        bool isEchoRequest = (icmpType == 8);  // ICMP Echo Request
                        bool isEchoReply = (icmpType == 0);    // ICMP Echo Reply

                        // Extract payload
                        packet.payload = packetData + ipHeaderOffset + 8; // ICMP header is typically 8 bytes
                    }
                    else
                    {
                        packet.protocol_type = "other";
                        logger.Log("Invalid protocol");
                        //std::cerr << "Invalid protocol" << std::endl;
                    }
                }
                else if (ethType == 0x86DD)
                { // IPv6 ethertype
                    // Check if there is a Radiotap header
                    uint8_t radiotapHeaderLength = 0;
                    if (header.caplen >= 3)
                    {
                        radiotapHeaderLength = packetData[2];
                    }

                    // Check if IEEE 802.11 header follows the Radiotap header
                    uint8_t ieee80211FrameOffset = radiotapHeaderLength;

                    // Assuming ieee80211FrameOffset is the offset to the beginning of the IEEE 802.11 header
                    uint16_t frameControlField = (packetData[ieee80211FrameOffset + 1] << 8) | packetData[ieee80211FrameOffset];

                    // Assuming the data frame control field is 2 bytes
                    uint16_t dataFrameControlField = (packetData[ieee80211FrameOffset + 24 + 1] << 8) | packetData[ieee80211FrameOffset + 24];

                    // Extract IEEE 802.11 header information
                    uint8_t frameType = (dataFrameControlField & 0x0C) >> 2;  // Extract frame control type bits
                    uint8_t frameSubtype = (dataFrameControlField & 0xF0) >> 4; // Extract frame subtype bits

                    // Define header size based on frame type and subtype
                    uint8_t ieee80211HeaderSize = 24; // Common header size

                    if (frameType == 0x00 && frameSubtype == 0x08)
                    {
                        // Management frame subtype 0x08 (Beacon frame) example
                        // Beacon frames have a fixed size of 24 bytes for the management header
                        ieee80211HeaderSize = 24;
                    }
                    else if (frameType == 0x02)
                    {
                        // Data frame example
                        ieee80211HeaderSize += 2;
                    }

                    // Assuming the presence of an IPv6 payload
                    uint8_t ipv6HeaderOffset = ieee80211FrameOffset + ieee80211HeaderSize;

                    // Extract IPv6 header information
                    uint8_t versionTrafficClassFlowLabel = packetData[ipv6HeaderOffset];
                    uint8_t payloadLength = packetData[ipv6HeaderOffset + 4];
                    uint8_t nextHeader = packetData[ipv6HeaderOffset + 6]; // Protocol type following IPv6 header
                    uint8_t hopLimit = packetData[ipv6HeaderOffset + 7];   // TTL

                    packet.ip_ttl = hopLimit;

                    // Extract source and destination IPv6 addresses
                    in6_addr sourceIPv6;
                    in6_addr destIPv6;
                    std::memcpy(&sourceIPv6, &packetData[ipv6HeaderOffset + 8], sizeof(in6_addr));
                    std::memcpy(&destIPv6, &packetData[ipv6HeaderOffset + 24], sizeof(in6_addr));

                    // Convert byte arrays to string representation
                    packet.ip6_src = sourceIPv6;
                    packet.ip6_dst = destIPv6;

                    ipHeader = reinterpret_cast<const IP*>(packetData + headerSize);

                    const IPV6_HEADER* ipHeader1 = reinterpret_cast<const IPV6_HEADER*>(packetData + headerSize);

                    // Extract source and destination bytes
                    uint16_t srcBytes = (ipHeader1->sourceIPv6.u.Word[4] << 8) | ipHeader1->sourceIPv6.u.Word[5];
                    uint16_t dstBytes = (ipHeader1->destIPv6.u.Word[4] << 8) | ipHeader1->destIPv6.u.Word[5];

                    // Extract the flags, payload, source port, and destination port (if applicable)
                    if (nextHeader == IPPROTO_TCP)
                    {
                        packet.protocol_type = "tcp";
                        // Extract TCP header information
                        packet.source_port = (packetData[ipv6HeaderOffset + 40] << 8) | packetData[ipv6HeaderOffset + 41];
                        packet.dest_port = (packetData[ipv6HeaderOffset + 42] << 8) | packetData[ipv6HeaderOffset + 43];

                        // Extract the TCP flag
                        packet.flags = packetData[ipv6HeaderOffset + 54];

                        // Extract payload
                        packet.payload = packetData + ipv6HeaderOffset + 40; // Adjust the offset based on the actual header lengths
                    }
                    else if (nextHeader == IPPROTO_UDP)
                    {
                        packet.protocol_type = "udp";
                        // Extract UDP header information
                        packet.source_port = (packetData[ipv6HeaderOffset + 40] << 8) | packetData[ipv6HeaderOffset + 41];
                        packet.dest_port = (packetData[ipv6HeaderOffset + 42] << 8) | packetData[ipv6HeaderOffset + 43];
                        uint16_t udpLength = (packetData[ipv6HeaderOffset + 44] << 8) | packetData[ipv6HeaderOffset + 45];

                        // No flags for UDP

                        packet.payload = packetData + ipv6HeaderOffset + 40; // Adjust the offset based on the actual header lengths
                    }
                    else if (nextHeader == IPPROTO_ICMPV6)
                    {
                        packet.protocol_type = "icmp";
                        // Extract ICMPv6 header information
                        uint8_t icmpType = packetData[ipv6HeaderOffset + 40];
                        uint8_t icmpCode = packetData[ipv6HeaderOffset + 41];

                        // ICMPv6 does not have ports, so no need to extract source and destination ports

                        // Flag-like logic based on ICMPv6 Type
                        // (You can process the messages further to determine the flag returned)
                        bool isEchoRequest = (icmpType == 128); // ICMPv6 Echo Request
                        bool isEchoReply = (icmpType == 129);   // ICMPv6 Echo Reply

                        packet.payload = packetData + ipv6HeaderOffset + 40; // Adjust the offset based on the actual header lengths
                    }
                    else
                    {
                        packet.protocol_type = "other";
                        logger.Log("Invalid protocol");
                        //std::cerr << "Invalid protocol" << std::endl;
                    }
                }
                else
                {
                    logger.Log("Unknown version");
                    //std::cerr << "Unknown version" << std::endl;
                }
            }
            else
            {
                logger.Log("Unsupported link layer protocol\n");
                //std::cerr << "Unsupported link layer protocol" << std::endl;
            }
            // create the machine learning model datapoint
            AttributeExtractor(packetData, packet, header, ipHeader, connectionTimeInSeconds, headerSize, ipHeaderLength, srcBytes, dstBytes);
        }
        else
        {
            logger.Log("An error occurred\n");
            //std::cerr << "An error occurred\n" << std::endl;
        }

        std::string interfaceId = iface.interfaceName;

        // Store the packet details in the shared vector
        std::lock_guard<std::mutex> lock(capturedPacketsMutex);

        if (capturedPackets.find(interfaceId) == capturedPackets.end())
        {
            // If the interface doesn't exist in the map, create it
            capturedPackets[interfaceId] = std::vector<Packet>();
        }

        capturedPacketsArr.push_back(packet);

        pcap_close(handle);
    }

    // Stop packet capture
    void PacketCollector::StopCapture()
    {
        // Signal the capture threads to stop
        isCapturing.store(false, std::memory_order_relaxed);

        // Wait for all the threads to finish
        for (auto& thread : threads)
        {
            thread.join();
        }

        // Close the pcap handles for all interfaces
        for (auto& iface : networkInterfaces)
        {
            if (iface.pcapHandle != nullptr)
            {
                pcap_close(iface.pcapHandle);
            }
        }

        return;
    }

    // returning collected packets
    std::map<std::string, std::vector<Packet>> PacketCollector::GetCapturedPackets()
    {
        std::lock_guard<std::mutex> lock(capturedPacketsMutex);
        return capturedPackets;
    }

    // endpoint data collection init
    EndpointDataCollector::EndpointDataCollector(const std::string& ipAddress, NetworkLogger& logger) : ipAddress(ipAddress), logger(logger) {}

    // Function to collect endpoint data
    EndpointData EndpointDataCollector::CollectData()
    {
        EndpointData endpointData;

        try
        {
            // Build the nmap command to scan the target IP address
            std::string command = "nmap -T4 -O " + ipAddress;

            // Open a pipe to run the nmap command and capture the output
            std::array<char, 128> buffer{};
            std::string result;
            std::shared_ptr<FILE> pipe(_popen(command.c_str(), "r"), _pclose);
            if (!pipe)
            {
                throw std::runtime_error("popen() failed");
            }

            // Read the output of the command into the result string
            while (!feof(pipe.get()))
            {
                if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
                {
                    result += buffer.data();
                }
            }

            // Parse the nmap output to extract relevant data
            // In a real-world scenario, you would need to parse the output accordingly

            // Example: Extract operating system information
            size_t osPos = result.find("OS details: ");
            if (osPos != std::string::npos)
            {
                endpointData.operatingSystem = result.substr(osPos + 12, result.find('\n', osPos) - osPos - 12);
            }

            // Example: Extract MAC address
            size_t macPos = result.find("MAC Address: ");
            if (macPos != std::string::npos)
            {
                endpointData.macAddress = result.substr(macPos + 13, result.find('\n', macPos) - macPos - 13);
            }

            // Example: Extract hostname
            size_t hostnamePos = result.find("Nmap scan report for ");
            if (hostnamePos != std::string::npos) {
                endpointData.hostname = result.substr(hostnamePos + 21, result.find('\n', hostnamePos) - hostnamePos - 21);
            }

            // Example: Extract user accounts (customize as needed)
            size_t userAccountsPos = result.find("User accounts: ");
            if (userAccountsPos != std::string::npos) {
                endpointData.userAccounts = result.substr(userAccountsPos + 15, result.find('\n', userAccountsPos) - userAccountsPos - 15);
            }

            // Example: Extract installed software (customize as needed)
            size_t softwarePos = result.find("Installed software: ");
            if (softwarePos != std::string::npos) {
                // Split the list of installed software into individual items
                std::string softwareList = result.substr(softwarePos + 19, result.find('\n', softwarePos) - softwarePos - 19);
                size_t start = 0;
                size_t end = softwareList.find(',');
                while (end != std::string::npos) {
                    endpointData.installedSoftware.push_back(softwareList.substr(start, end - start));
                    start = end + 2;  // Skip comma and space
                    end = softwareList.find(',', start);
                }
                endpointData.installedSoftware.push_back(softwareList.substr(start));  // Add the last item
            }

            // Example: Extract network connections (customize as needed)
            size_t networkConnectionsPos = result.find("Network connections: ");
            if (networkConnectionsPos != std::string::npos) {
                endpointData.networkConnections = result.substr(networkConnectionsPos + 21, result.find('\n', networkConnectionsPos) - networkConnectionsPos - 21);
            }

            // Example: Extract security software (customize as needed)
            size_t securitySoftwarePos = result.find("Security software: ");
            if (securitySoftwarePos != std::string::npos) {
                endpointData.securitySoftware = result.substr(securitySoftwarePos + 19, result.find('\n', securitySoftwarePos) - securitySoftwarePos - 19);
            }

            // Example: Extract hardware information (customize as needed)
            size_t hardwareInfoPos = result.find("Hardware information: ");
            if (hardwareInfoPos != std::string::npos) {
                endpointData.hardwareInformation = result.substr(hardwareInfoPos + 21, result.find('\n', hardwareInfoPos) - hardwareInfoPos - 21);
            }

            // Example: Extract network traffic (customize as needed)
            size_t networkTrafficPos = result.find("Network traffic: ");
            if (networkTrafficPos != std::string::npos) {
                endpointData.networkTraffic = result.substr(networkTrafficPos + 17, result.find('\n', networkTrafficPos) - networkTrafficPos - 17);
            }

            // Example: Extract security events (customize as needed)
            size_t securityEventsPos = result.find("Security events: ");
            if (securityEventsPos != std::string::npos) {
                endpointData.securityEvents = result.substr(securityEventsPos + 17, result.find('\n', securityEventsPos) - securityEventsPos - 17);
            }

            // Example: Extract location (customize as needed)
            size_t locationPos = result.find("Location: ");
            if (locationPos != std::string::npos) {
                endpointData.location = result.substr(locationPos + 10, result.find('\n', locationPos) - locationPos - 10);
            }

            // Finally, return the populated endpointData struct
            endpointData.ipAddress = ipAddress;
            endpointData.endpointName = hostnamePos;  // Set the endpoint name
            endpointData.location = locationPos;
            endpointData.macAddress = macPos;
            endpointData.securityEvents = securityEventsPos;
            endpointData.operatingSystem = osPos;
            endpointData.networkTraffic = networkTrafficPos;
            endpointData.networkConnections = networkConnectionsPos;
            endpointData.securitySoftware = securitySoftwarePos;

            return endpointData;
        }
        catch (const std::exception& e)
        {
            // Handle any exceptions or errors that occur during data collection
            logger.Log(e.what());
            std::cerr << "Error: " << e.what() << std::endl;
            // Return an empty or error state EndpointData if needed
            return endpointData;  // You may define an error state in the struct
        }
    }

    // network logs
    LogCollector::LogCollector(const std::string& logFilePath) : logFilePath(logFilePath) {}

    std::string LogCollector::CollectData()
    {
        std::string data;

        try
        {
            // Open the log file for reading
            std::fstream logFile(logFilePath);

            if (!logFile.is_open())
            {
                std::cerr << "Error: Failed to open log file: " << logFilePath << std::endl;
                std::cout << "Error: Failed to open log file: " << logFilePath << std::endl;
                return ""; // Return an empty string if the file cannot be opened
            }

            // Read the contents of the log file into a string
            data.assign((std::istreambuf_iterator<char>(logFile)), std::istreambuf_iterator<char>());

            // Close the file
            logFile.close();

            // Clear the log file contents
            std::ofstream clearLogFile(logFilePath);
            clearLogFile.close();
        }
        catch (const std::exception& e)
        {
            std::cout << "Error: Exception occurred during log collection: " << e.what() << std::endl;
            return "";
        }

        return data;
    }

    // data container to store training and testing data
    Data::Data()
    {
        featureVector = std::make_shared<std::vector<double>>();
    }

    Data::~Data()
    {
        // clean dynamically allocated memory
    }

    template<class Archive>
    void Data::serialize(Archive& ar, const unsigned int version)
    {
        ar& featureVector;
        ar& label;
        ar& enumLabel;
        ar& distance;
    }

    void Data::SetFeatureVector(std::shared_ptr<std::vector<double>> vect)
    {
        featureVector = vect;
    }

    void Data::AppendToFeatureVector(const double& val)
    {
        featureVector->push_back(val);
    }

    void Data::SetLabel(std::string val) 
    {
        label = val;
    }

    void Data::SetEnumLabel(int val)
    {
        enumLabel = val;
    }

    int Data::GetFeatureVectorSize()
    {
        return featureVector->size();
    }

    std::string Data::GetLabel()
    {
        return label;
    }

    int Data::GetEnumLabel()
    {
        return enumLabel;
    }

    std::shared_ptr<std::vector<double>> Data::GetFeatureVector()
    {
        return featureVector;
    }

    void Data::SetDistance(double val)
    {
        distance = val;
    }

    double Data::GetDistance()
    {
        return  distance;
    }

    // data handler

    // constructor
    DataHandler::DataHandler()
    {
        // initialization of data array pointers
       dataArray = std::make_shared<std::vector<std::shared_ptr<Data>>>();
       trainingData = std::make_shared<std::vector<std::shared_ptr<Data>>>();
       testData = std::make_shared<std::vector<std::shared_ptr<Data>>>();
       validationData = std::make_shared<std::vector<std::shared_ptr<Data>>>();
    }

    // destructor
    DataHandler::~DataHandler()
    {
        _fcloseall();
    }

    template<class Archive>
    void DataHandler::serialize(Archive& ar, const unsigned int version)
    {
        ar& dataArray;
        ar& trainingData;
        ar& testData;
        ar& validationData;
    }

    // save DataHandler instance
    void DataHandler::SaveDataHandler(std::string& fileName)
    {
        std::ofstream ofs(fileName);
        boost::archive::text_oarchive oa(ofs);
        oa << *this;
    }

    // load the DataHandler instace
    void DataHandler::LoadDataHandler(std::string& fileName)
    {
        std::ifstream ifs(fileName);
        boost::archive::text_iarchive ia(ifs);
        ia >> *this;
    }

    std::shared_ptr<DataCollection::Data> DataHandler::CreateDataInstance(std::string line)
    {
        std::shared_ptr<Data> data = std::make_shared<Data>();

        if (line.empty())
        {
            std::cerr << "Invalid data: " << line << std::endl;
            return data;
        }

        // Define maps to store label encodings for the categorical columns
        std::unordered_map<std::string, int> protocolType;
        std::unordered_map<std::string, int> service;
        std::unordered_map<std::string, int> flag;

        int protocolTypeCounter = 0;
        int serviceCounter = 0;
        int flagCounter = 0;
        
        
        std::istringstream ss(line);
        std::string token;
        
        std::vector<std::string> fields; // store all the fields in avector

        while (std::getline(ss, token, ','))
        {
            fields.push_back(token);
        }

        // parse the data point features
        if (fields.size() == 41)
        {
            // Encode protocol type
            if (protocolType.find(fields[1]) == protocolType.end())
            {
                protocolType[fields[1]] = protocolTypeCounter++;
            }
            data->AppendToFeatureVector(protocolType[fields[1]]);

            // Encode service
            if (service.find(fields[2]) == service.end())
            {
                service[fields[2]] = serviceCounter++;
            }
            data->AppendToFeatureVector(service[fields[2]]);

            // Encode flag
            if (flag.find(fields[3]) == flag.end())
            {
                flag[fields[3]] = flagCounter++;
            }
            data->AppendToFeatureVector(flag[fields[3]]);

            // parse and convert each field to a double and append it to the feature vector
            for (size_t i = 4; i < fields.size(); i++)
            {
                try
                {
                    double value = std::stod(fields[i]);
                    data->AppendToFeatureVector(value);
                }
                catch (const std::invalid_argument e)
                {
                    std::cerr << "Invalid argument: " << e.what() << " for field: " << fields[i] << std::endl;
                    continue;
                }
            }

        }
        
        std::cout << "Successfully read and stored feature vectors, " << dataArray->size() << std::endl;
        return data;
    }

    std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> DataHandler::ReadFeatureVector(std::string path)
    {
        std::ifstream file(path);        

        if (!file.is_open())
        {
            std::cerr << "Failed to open the CSV file: " << path << std::endl;
            return testData;
        }

        std::string line;
        std::getline(file, line); // skip the header

        printf("Done getting input file header\n");

        // Define maps to store label encodings for the categorical columns
        std::unordered_map<std::string, int> protocolType;
        std::unordered_map<std::string, int> service;
        std::unordered_map<std::string, int> flag;

        int protocolTypeCounter = 0;
        int serviceCounter = 0;
        int flagCounter = 0;

        while (std::getline(file, line))
        {
            std::istringstream ss(line);
            std::string token;

            std::shared_ptr<Data> data = std::make_shared<Data>();
            std::vector<std::string> fields; // store all the fields in avector

            while (std::getline(ss, token, ','))
            {
                fields.push_back(token);
            }

            // parse the data point features
            if (fields.size() == 41)
            {
                // Encode protocol type
                if (protocolType.find(fields[1]) == protocolType.end())
                {
                    protocolType[fields[1]] = protocolTypeCounter++;
                }
                data->AppendToFeatureVector(protocolType[fields[1]]);

                // Encode service
                if (service.find(fields[2]) == service.end())
                {
                    service[fields[2]] = serviceCounter++;
                }
                data->AppendToFeatureVector(service[fields[2]]);

                // Encode flag
                if (flag.find(fields[3]) == flag.end())
                {
                    flag[fields[3]] = flagCounter++;
                }
                data->AppendToFeatureVector(flag[fields[3]]);

                // parse and convert each field to a double and append it to the feature vector
                for (size_t i = 4; i < fields.size(); i++)
                {
                    try
                    {
                        double value = std::stod(fields[i]);
                        data->AppendToFeatureVector(value);
                    }
                    catch(const std::invalid_argument e)
                    {
                        std::cerr << "Invalid argument: " << e.what() << " for field: " << fields[i] << std::endl;
                        continue;
                    }
                }

                testData->push_back(data);                
                //dataArray->push_back(data);
               
            }            
            
        }
        std::cout << "Successfully read and stored feature vectors, " << dataArray->size() << std::endl;
        return testData;        
       
    }

    void DataHandler::ReadFeatureLabels(std::string path)
    {
        std::ifstream file(path);

        if (!file.is_open())
        {
            std::cerr << "Failed to open the CSV file: " << path << std::endl;
            return;
        }

        std::string line;
        std::getline(file, line); // Read and discard the header

        printf("Done getting label file header\n");

        int dataIndex = 0;
        
        while (std::getline(file, line))
        {               
            std::istringstream ss(line);
            std::string token;

            std::vector<std::string> fields;

            // split the line into columns
            while (std::getline(ss, token, ','))
            {
                fields.push_back(token);
            }

            // Extract the label
            if (dataIndex < dataArray->size())
            {
                // label is the last column in the csv file
                std::string label = fields.back();

                // append label to corresponding data point
                (*dataArray)[dataIndex]->SetLabel(label);
                dataIndex++;
            }
            else
            {
                std::cerr << "Error: Mismatch between the number of labels and data points." << std::endl;
                return;
            }
        }

        std::cout << "Successfully read and stored label" << std::endl;
        
    }

    void DataHandler::SplitData()
    {
        std::random_device rd;
        std::default_random_engine engine(rd());

        // Shuffle the data randomly
        std::shuffle(dataArray->begin(), dataArray->end(), engine);

        size_t dataSize = dataArray->size();
        int trainSize = static_cast<int>(dataSize * TRAIN_SET_PERCENT);
        int testSize = static_cast<int>(dataSize * TEST_SET_PERCENT);
        size_t validateSize = dataSize - trainSize - testSize;

        trainingData->clear();
        testData->clear();
        validationData->clear();

        for (int i = 0; i < dataSize; ++i)
        {
            if (i < trainSize)
            {
                trainingData->push_back(dataArray->at(i));
            }
            else if (i < trainSize + testSize)
            {
                testData->push_back(dataArray->at(i));
            }
            else
            {
                validationData->push_back(dataArray->at(i));
            }
        }

        std::cout << "Training data size: " << trainingData->size() << std::endl;
        std::cout << "Testing data size: " << testData->size() << std::endl;
        std::cout << "Validation data size: " << validationData->size() << std::endl;
    }

    void DataHandler::CountClasses()
    {
        int count = 0;
        for (unsigned i = 0; i < dataArray->size(); i++)
        {
            if (classMap.find(dataArray->at(i)->GetLabel()) == classMap.end())
            {
                classMap[dataArray->at(i)->GetLabel()] = count;
                dataArray->at(i)->SetEnumLabel(count);
                count++;
            }
        }
        numClasses = count;
        std::cout << "Succesfully extracted unique classes, " << numClasses << std::endl;
    }

    std::shared_ptr<std::vector<std::shared_ptr<Data>>> DataHandler::GetTrainingData()
    {
        return trainingData;
    }

    std::shared_ptr<std::vector<std::shared_ptr<Data>>> DataHandler::GetTestData()
    {
        return testData;
    }

    std::shared_ptr<std::vector<std::shared_ptr<Data>>> DataHandler::GetValidationData()
    {
        return validationData;
    }   

}