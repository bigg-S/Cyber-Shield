#include "data.h"


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
                std::cerr << "Failed to retrieve the PATH variable." << std::endl;
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
    std::vector<NetworkInterface> NetworkHelperFunctions::GetNetworkInterfaces(const std::string& networkId)
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
            std::cerr << "Error: Error during metadata collection: " << e.what() << std::endl;
            return "Error: Metadata collection failed";
        }
    }

    // packet capture init
    PacketCollector::PacketCollector(const std::vector<NetworkInterface>& networkInterfaces, int packetCount, NetworkLogger& logger)
        : networkInterfaces(networkInterfaces), packetCount(packetCount), logger(logger) {}

    PacketCollector::~PacketCollector()
    {
        if (isCapturing)
        {
            StopCapture();
        }
    }

    // Start packet capture method
    void PacketCollector::StartCapture()
    {
        // Check if packet capturing is in progress
        if (isCapturing)
        {
            logger.Log("Already capturing");
            std::cerr << "Already capturing" << std::endl;
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

        // Wait for all threads to be ready to capture
        while (startBarrier.load(std::memory_order_relaxed) < networkInterfaces.size())
        {
            std::this_thread::yield();
        }

        isCapturing.store(true, std::memory_order_relaxed);
    }

    // Stop packet capture
    void PacketCollector::StopCapture()
    {
        if (!isCapturing)
        {
            std::cerr << "Not currently capturing" << std::endl;
            return;
        }

        // Signal the capture threads to stop
        isCapturing = false;

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

            startBarrier.fetch_sub(1, std::memory_order_relaxed); // Release the thread from the barrier
            return;
        }

        while (isCapturing.load(std::memory_order_relaxed))
        {
            struct pcap_pkthdr header;
            const u_char* packetData = pcap_next(pcapHandle, &header);

            if (packetData != nullptr)
            {
                ProcessPacket(packetData, header, iface);
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
    void PacketCollector::ProcessPacket(const u_char* packetData, const struct pcap_pkthdr& header, const NetworkInterface& iface)
    {
        NetworkPacket packet;
        // Buffer to store the formatted timestamp
        char timestampBuffer[26];
        time_t timestamp = header.ts.tv_sec;

        if (timestamp > 0)
        {
            // Ensure timestampBuffer is large enough to hold the formatted timestamp
            if (ctime_s(timestampBuffer, sizeof(timestampBuffer), &timestamp) == 0)
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

        // Determine the interface type
        if (iface.interfaceDescription.find("Ethernet") != std::string::npos)
        {
            // Check if the captured packet is large enough to contain the Ethernet header
            if (header.caplen >= 14) // Assuming Ethernet frame size is at least 14 bytes (size of Ethernet header)
            {
                const u_char* ethHeader = packetData;
                uint16_t etherType = ntohs(*reinterpret_cast<const uint16_t*>(ethHeader + 12)); // Extract the Ethernet frame type

                if (etherType == 0x0800) // 0x0800 represents IPv4 Ethernet frame
                {
                    const u_char* ipHeader = packetData + 14; // Skip Ethernet header
                    struct Ipv4Header* ip = (struct Ipv4Header*)ipHeader;

                    // Extract IP header fields
                    packet.ipHeader.version = (ip->version >> 4) & 0x0F;
                    packet.ipHeader.headerLength = (ip->headerLength & 0x0F) * 4;
                    packet.ipHeader.tos = ip->tos;
                    packet.ipHeader.totalLength = ntohs(ip->totalLength);
                    packet.ipHeader.identification = ntohs(ip->identification);
                    packet.ipHeader.flagsFragmentOffset = ntohs(ip->flagsFragmentOffset);
                    packet.ipHeader.ttl = ip->ttl;
                    packet.ipHeader.protocol = ip->protocol;
                    packet.ipHeader.headerChecksum = ntohs(ip->headerChecksum);

                    // Convert IP addresses to string representations
                    char sourceIpString[INET_ADDRSTRLEN];
                    char destinationIpString[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &(ip->sourceIp), sourceIpString, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(ip->destinationIp), destinationIpString, INET_ADDRSTRLEN);

                    packet.ipHeader.sourceIp = sourceIpString;
                    packet.ipHeader.destinationIp = destinationIpString;

                    // Assuming payload follows the IP header
                    const u_char* payload = packetData + 14 + (ip->headerLength * 4); // Skip Ethernet + IP header

                    // Calculate the payload length
                    uint16_t payloadLength = header.caplen - 14 - (ip->headerLength * 4); // Skip Ethernet + IP header

                    // Copy payload data to the NetworkPacket
                    packet.applicationData.assign(payload, payload + payloadLength);

                    // Store the packet details in the shared vector
                    std::lock_guard<std::mutex> lock(capturedPacketsMutex);
                    capturedPacketsArr.push_back(packet);
                }
                else if (etherType == 0x86DD) // 0x86DD represents IPv6 Ethernet frame
                {
                    const u_char* ipv6Header = packetData + 14; // Skip Ethernet header
                    struct IPv6Header* ip = (struct IPv6Header*)ipv6Header;

                    // Extract IPv6 header fields
                    // Extract required fields from the IPv6 header

                    // Convert IP addresses to string representations
                    char sourceIpString[INET6_ADDRSTRLEN];
                    char destinationIpString[INET6_ADDRSTRLEN];

                    inet_ntop(AF_INET6, &(ip->sourceIp), sourceIpString, INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, &(ip->destinationIp), destinationIpString, INET6_ADDRSTRLEN);

                    packet.ipHeader.sourceIp = sourceIpString;
                    packet.ipHeader.destinationIp = destinationIpString;

                    // Assuming payload follows the IPv6 header
                    const u_char* payload = packetData + 14 + 40; // Skip Ethernet + IPv6 header

                    // Calculate the payload length
                    uint16_t payloadLength = header.caplen - 14 - 40; // Skip Ethernet + IPv6 header

                    // Copy payload data to the NetworkPacket
                    packet.applicationData.assign(payload, payload + payloadLength);

                    // Store the packet details in the shared vector
                    std::lock_guard<std::mutex> lock(capturedPacketsMutex);
                    capturedPacketsArr.push_back(packet);
                }
                else
                {
                    logger.Log("Unsupported Ethernet frame type");
                    std::cerr << "Unsupported Ethernet frame type" << std::endl;
                }
            }
            else
            {
                logger.Log("Invalid Ethernet packet");
                std::cerr << "Invalid Ethernet packet" << std::endl;
            }
        }
        // Determine the interface type
        if (iface.interfaceDescription.find("Wi-Fi") != std::string::npos)
        {
            // Check if the captured packet is large enough to contain the Wi-Fi header
            if (header.caplen >= 24) // Assuming Wi-Fi frame size is at least 24 bytes (size of Wi-Fi header)
            {
                const u_char* wifiHeader = packetData;

                // Extract the frame control field (2 bytes)
                uint16_t frameControl = wifiHeader[0] | (wifiHeader[1] << 8);

                if ((frameControl & 0x0F00) == 0x0800) // 0x0800 represents IPv4 in Wi-Fi frame
                {
                    const u_char* ipHeader = packetData + 24; // Skip Wi-Fi header
                    struct Ipv4Header* ip = (struct Ipv4Header*)ipHeader;

                    // Extract IP header fields
                    packet.ipHeader.version = (ip->version >> 4) & 0x0F;
                    packet.ipHeader.headerLength = (ip->headerLength & 0x0F) * 4;
                    packet.ipHeader.tos = ip->tos;
                    packet.ipHeader.totalLength = ntohs(ip->totalLength);
                    packet.ipHeader.identification = ntohs(ip->identification);
                    packet.ipHeader.flagsFragmentOffset = ntohs(ip->flagsFragmentOffset);
                    packet.ipHeader.ttl = ip->ttl;
                    packet.ipHeader.protocol = ip->protocol;
                    packet.ipHeader.headerChecksum = ntohs(ip->headerChecksum);

                    // Convert IP addresses to string representations
                    char sourceIpString[INET_ADDRSTRLEN];
                    char destinationIpString[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &(ip->sourceIp), sourceIpString, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(ip->destinationIp), destinationIpString, INET_ADDRSTRLEN);

                    packet.ipHeader.sourceIp = sourceIpString;
                    packet.ipHeader.destinationIp = destinationIpString;

                    // Assuming payload follows the IP header
                    const u_char* payload = packetData + 20; // Skip Wi-Fi + IP header (assuming IP header is 20 bytes)

                    // Calculate the payload length
                    uint16_t payloadLength = header.caplen - 24 - 20; // Skip Wi-Fi header and IP header

                    // Copy payload data to the NetworkPacket
                    packet.applicationData.assign(payload, payload + payloadLength);

                    // Store the packet details in the shared vector
                    std::lock_guard<std::mutex> lock(capturedPacketsMutex);
                    capturedPacketsArr.push_back(packet);
                }
                else if ((frameControl & 0x0F00) == 0x86DD) // 0x86DD represents IPv6 in Wi-Fi frame
                {
                    const u_char* ipv6Header = packetData + 24; // Skip Wi-Fi header
                    struct IPv6Header* ip = (struct IPv6Header*)ipv6Header;

                    // Extract IPv6 header fields
                    // Extract required fields from the IPv6 header

                     // Convert IP addresses to string representations
                    char sourceIpString[INET6_ADDRSTRLEN];
                    char destinationIpString[INET6_ADDRSTRLEN];

                    inet_ntop(AF_INET6, &(ip->sourceIp), sourceIpString, INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, &(ip->destinationIp), destinationIpString, INET6_ADDRSTRLEN);

                    packet.ipHeader.sourceIp = sourceIpString;
                    packet.ipHeader.destinationIp = destinationIpString;

                    // Assuming payload follows the IPv6 header
                    const u_char* payload = packetData + 24 + 40; // Skip Wi-Fi + IPv6 header

                    // Calculate the payload length
                    uint16_t payloadLength = header.caplen - 24 - 40; // Skip Wi-Fi header and IPv6 header

                    // Copy payload data to the NetworkPacket
                    packet.applicationData.assign(payload, payload + payloadLength);

                    // Store the packet details in the shared vector
                    std::lock_guard<std::mutex> lock(capturedPacketsMutex);
                    capturedPacketsArr.push_back(packet);
                }
                else
                {
                    logger.Log("Unsupported Wi-Fi frame type");
                    std::cerr << "Unsupported Wi-Fi frame type" << std::endl;
                }
            }
            else
            {
                logger.Log("Invalid Wi-Fi packet");
                std::cerr << "Invalid Wi-Fi packet" << std::endl;
            }
        }
        // Determine the interface type
        if (iface.interfaceDescription.find("Loopback") != std::string::npos)
        {
            // Check if the captured packet is large enough to contain the IP header
            if (header.caplen >= 20) // Assuming a minimal IPv4 header size is 20 bytes
            {
                const u_char* ipHeader = packetData;
                struct Ipv4Header* ip = (struct Ipv4Header*)ipHeader;

                // Extract IP header fields
                packet.ipHeader.version = (ip->version >> 4) & 0x0F;
                packet.ipHeader.headerLength = (ip->headerLength & 0x0F) * 4;
                packet.ipHeader.tos = ip->tos;
                packet.ipHeader.totalLength = ntohs(ip->totalLength);
                packet.ipHeader.identification = ntohs(ip->identification);
                packet.ipHeader.flagsFragmentOffset = ntohs(ip->flagsFragmentOffset);
                packet.ipHeader.ttl = ip->ttl;
                packet.ipHeader.protocol = ip->protocol;
                packet.ipHeader.headerChecksum = ntohs(ip->headerChecksum);

                // Convert IP addresses to string representations
                char sourceIpString[INET_ADDRSTRLEN];
                char destinationIpString[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &(ip->sourceIp), sourceIpString, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ip->destinationIp), destinationIpString, INET_ADDRSTRLEN);

                packet.ipHeader.sourceIp = sourceIpString;
                packet.ipHeader.destinationIp = destinationIpString;

                // Assuming payload follows the IP header
                const u_char* payload = packetData + 20; // Skip IP header

                // Calculate the payload length
                uint16_t payloadLength = header.caplen - 20; // Skip IP header

                // Copy payload data to the NetworkPacket
                packet.applicationData.assign(payload, payload + payloadLength);

                // Store the packet details in the shared vector
                std::lock_guard<std::mutex> lock(capturedPacketsMutex);
                capturedPacketsArr.push_back(packet);
            }
            else if (header.caplen >= 40) // Assuming a minimal IPv6 header size is 40 bytes
            {
                const u_char* ipv6Header = packetData;
                struct IPv6Header* ip = (struct IPv6Header*)ipv6Header;

                // Extract IPv6 header fields
                // Extract required fields from the IPv6 header

                // Convert IP addresses to string representations
                char sourceIpString[INET6_ADDRSTRLEN];
                char destinationIpString[INET6_ADDRSTRLEN];

                inet_ntop(AF_INET6, &(ip->sourceIp), sourceIpString, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &(ip->destinationIp), destinationIpString, INET6_ADDRSTRLEN);

                packet.ipHeader.sourceIp = sourceIpString;
                packet.ipHeader.destinationIp = destinationIpString;

                // Assuming payload follows the IPv6 header
                const u_char* payload = packetData + 40; // Skip IPv6 header

                // Calculate the payload length
                uint16_t payloadLength = header.caplen - 40; // Skip IPv6 header

                // Copy payload data to the NetworkPacket
                packet.applicationData.assign(payload, payload + payloadLength);

                // Store the packet details in the shared vector
                std::lock_guard<std::mutex> lock(capturedPacketsMutex);
                capturedPacketsArr.push_back(packet);
            }
            else
            {
                logger.Log("Invalid Loopback packet");
                std::cerr << "Invalid Loopback packet" << std::endl;
            }
        }
        else if (iface.interfaceDescription.find("PPP") != std::string::npos)
        {
            // PPP interface processing logic
            // Handle PPP packets based on your requirements

            // Check if the captured packet is large enough to contain the PPP header
            if (header.caplen >= 2)
            {
                const u_char* pppHeader = packetData;

                // Extract PPP protocol field (2 bytes)
                uint16_t protocol = ntohs(*reinterpret_cast<const uint16_t*>(pppHeader));

                // Check protocol type (for example, IPv4 or IPv6)
                if (protocol == 0x0021) // 0x0021 represents IPv4 protocol in PPP
                {
                    // Assuming a minimal IPv4 header size is 20 bytes
                    if (header.caplen >= 22)
                    {
                        const u_char* ipHeader = packetData + 2; // Skip PPP header
                        struct Ipv4Header* ip = (struct Ipv4Header*)ipHeader;

                        // Extract IP header fields
                        packet.ipHeader.version = (ip->version >> 4) & 0x0F;
                        packet.ipHeader.headerLength = (ip->headerLength & 0x0F) * 4;
                        packet.ipHeader.tos = ip->tos;
                        packet.ipHeader.totalLength = ntohs(ip->totalLength);
                        packet.ipHeader.identification = ntohs(ip->identification);
                        packet.ipHeader.flagsFragmentOffset = ntohs(ip->flagsFragmentOffset);
                        packet.ipHeader.ttl = ip->ttl;
                        packet.ipHeader.protocol = ip->protocol;
                        packet.ipHeader.headerChecksum = ntohs(ip->headerChecksum);

                        // Convert IP addresses to string representations
                        char sourceIpString[INET_ADDRSTRLEN];
                        char destinationIpString[INET_ADDRSTRLEN];

                        inet_ntop(AF_INET, &(ip->sourceIp), sourceIpString, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &(ip->destinationIp), destinationIpString, INET_ADDRSTRLEN);

                        packet.ipHeader.sourceIp = sourceIpString;
                        packet.ipHeader.destinationIp = destinationIpString;

                        // Assuming payload follows the IP header
                        const u_char* payload = packetData + 2 + (ip->headerLength * 4); // Skip PPP header + IP header

                        // Calculate the payload length
                        uint16_t payloadLength = header.caplen - 2 - (ip->headerLength * 4); // Skip PPP header + IP header

                        // Copy payload data to the NetworkPacket
                        packet.applicationData.assign(payload, payload + payloadLength);

                        // Store the packet details in the shared vector
                        std::lock_guard<std::mutex> lock(capturedPacketsMutex);
                        capturedPacketsArr.push_back(packet);
                    }
                    else
                    {
                        logger.Log("Invalid IPv4 packet in PPP interface");
                        std::cerr << "Invalid IPv4 packet in PPP interface" << std::endl;
                    }
                }
                else if (protocol == 0x0057) // 0x0057 represents IPv6 protocol in PPP
                {
                    // Assuming a minimal IPv6 header size is 40 bytes
                    if (header.caplen >= 42)
                    {
                        const u_char* ipv6Header = packetData + 2; // Skip PPP header
                        struct IPv6Header* ip = (struct IPv6Header*)ipv6Header;

                        // Extract IPv6 header fields
                        // Extract required fields from the IPv6 header

                        // Convert IP addresses to string representations
                        char sourceIpString[INET6_ADDRSTRLEN];
                        char destinationIpString[INET6_ADDRSTRLEN];

                        inet_ntop(AF_INET6, &(ip->sourceIp), sourceIpString, INET6_ADDRSTRLEN);
                        inet_ntop(AF_INET6, &(ip->destinationIp), destinationIpString, INET6_ADDRSTRLEN);

                        packet.ipHeader.sourceIp = sourceIpString;
                        packet.ipHeader.destinationIp = destinationIpString;

                        // Assuming payload follows the IPv6 header
                        const u_char* payload = packetData + 2 + 40; // Skip PPP header + IPv6 header

                        // Calculate the payload length
                        uint16_t payloadLength = header.caplen - 2 - 40; // Skip PPP header + IPv6 header

                        // Copy payload data to the NetworkPacket
                        packet.applicationData.assign(payload, payload + payloadLength);

                        // Store the packet details in the shared vector
                        std::lock_guard<std::mutex> lock(capturedPacketsMutex);
                        capturedPacketsArr.push_back(packet);
                    }
                    else
                    {
                        logger.Log("Invalid IPv6 packet in PPP interface");
                        std::cerr << "Invalid IPv6 packet in PPP interface" << std::endl;
                    }
                }
                else
                {
                    logger.Log("Unsupported PPP protocol");
                    std::cerr << "Unsupported PPP protocol" << std::endl;
                }
            }
            else
            {
                logger.Log("Invalid PPP packet");
                std::cerr << "Invalid PPP packet" << std::endl;
            }
        }

        else
        {
            logger.Log("Unknown interface type");
            std::cerr << "Unknown interface type" << std::endl;
        }

       
    }

    // returning collected packets
    std::map<std::string, std::vector<NetworkPacket>> PacketCollector::GetCapturedPackets()
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

}