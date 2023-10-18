
#include "data.h"


namespace DataCollection
{
    NetworkHelperFunctions::NetworkHelperFunctions(const std::string& ipAddress, const std::string& networkId, const std::string& subnetMask, pcap_if_t* dev, const std::string& target, const std::string& options)
        : ipAddress(ipAddress), networkId(networkId), subnetMask(subnetMask), dev(dev), target(target), options(options) {}

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
            return "Error: Network scan failed";
        }
    }

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


    bool NetworkHelperFunctions::IsInterfaceInNetwork(pcap_if_t* dev, const std::string& networkId)
    {
        if (dev != nullptr)
        {
            // get ip address and subnet mask from the interface
            for (pcap_addr* addr = dev->addresses; addr != nullptr; addr = addr->next)
            {
                if (addr->addr->sa_family == AF_INET) //IPv4 address
                {
                    // convert the IP address and subnet mask to string representation
                    char ipAddress[INET_ADDRSTRLEN];
                    char subnetMask[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &(reinterpret_cast<struct sockaddr_in*>(addr->addr))->sin_addr, subnetMask, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(reinterpret_cast<struct sockaddr_in*>(addr->netmask))->sin_addr, subnetMask, INET_ADDRSTRLEN);

                    // Ensure null-termination of the ipAddress string
                    ipAddress[INET_ADDRSTRLEN - 1] = '\0';

                    //compare the ip address with the identifier
                    if (IsIpAddressInNetwork(ipAddress, networkId, subnetMask))
                    {
                        return true;
                    }
                }
                else if (addr->addr->sa_family == AF_INET6)
                {
                    // convert ip address and subnet mask to string representations
                    char ipAddress[INET6_ADDRSTRLEN];
                    char subnetMask[INET6_ADDRSTRLEN];

                    inet_ntop(AF_INET6, &(reinterpret_cast<struct sockaddr_in6*>(addr->addr))->sin6_addr, ipAddress, INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, &(reinterpret_cast<struct sockaddr_in6*>(addr->netmask))->sin6_addr, subnetMask, INET6_ADDRSTRLEN);

                    // Ensure null-termination of the ipAddress string
                    ipAddress[INET_ADDRSTRLEN - 1] = '\0';

                    //compare the ip address with the network id
                    if (IsIpAddressInNetwork(ipAddress, networkId, subnetMask))
                    {
                        return true;
                    }

                }

            }
        }
        else
        {
            std::cerr << "No network interfaces found in this network\n";
        }        

        return false;
    }


    std::vector<NetworkInterface> NetworkHelperFunctions::GetNetworkInterfaces(const std::string& networkId)
    {
        std::vector<NetworkInterface> networkInterfaces;

        pcap_if_t* allDevs;
        char errbuf[PCAP_ERRBUF_SIZE];

        //retrieve the list of network interfaces
        if (pcap_findalldevs(&allDevs, errbuf) == -1)
        {
            std::cerr << "Failed to retrieve network interfaces" << errbuf << std::endl;
            return networkInterfaces;
        }

        pcap_if_t* dev;
        int i = 0;

        // iterate through the list of network interfaces
        for (dev = allDevs; dev != NULL; dev = dev->next)
        {
            // check if the network identifier matchhes the interfaces IP address or subnet
            bool isInNetwork = IsInterfaceInNetwork(dev, networkId);

            if (isInNetwork)
            {
                NetworkInterface networkInterface;
                networkInterface.interfaceName = dev->name;

                if (dev->description)
                {
                    networkInterface.interfaceDescription = dev->description;
                }
                else
                {
                    networkInterface.interfaceDescription = "N/A";
                }

                networkInterfaces.push_back(networkInterface);
            }
        }

        // free the list of network interfaces
        pcap_freealldevs(allDevs);

        return networkInterfaces;
    }

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
            std::cerr << "Error: Exception occurred during log collection: " << e.what() << std::endl;
            std::cout << "Error: Exception occurred during log collection: " << e.what() << std::endl;
            return "";
        }

        return data;
    }


    // collecting information about network adapters
    MetadataCollector::MetadataCollector() {}

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
            std::cerr << "Error: Error during metadata collection: " << e.what() << std::endl;
            return "Error: Metadata collection failed";
        }
    }


    PacketCollector::PacketCollector(const std::vector<std::string>& networkInterfaces, int packetCount)
        : networkInterfaces(networkInterfaces), packetCount(packetCount) {}

    std::vector<std::vector<NetworkPacket>> PacketCollector::CollectData()
    {
        try
        {
            // Initialize a vector to hold packet details from each thread
            std::vector<std::vector<NetworkPacket>> packetDetailsList(networkInterfaces.size());

            // A mutex to protect shared data
            std::mutex mutex;

            // A vector to hold thread objects
            std::vector<std::thread> threads;

            // Create a thread for each network interface
            for (int i = 0; i < networkInterfaces.size(); ++i)
            {
                threads.emplace_back([=, &packetDetailsList, &mutex]()
                    {
                        try
                {
                    // Open the network interface for packet capture
                    char errbuf[PCAP_ERRBUF_SIZE];
                    pcap_t* pcapHandle = pcap_open_live(networkInterfaces[i].c_str(), BUFSIZ, 1, 1000, errbuf);

                    if (pcapHandle == nullptr)
                    {
                        std::cerr << "Error: Failed to open network interface: " << errbuf << std::endl;
                        return;
                    }

                    // Capture packets
                    struct pcap_pkthdr header;
                    const u_char* packetData;
                    int packetNumber = 0;

                    while (packetNumber < packetCount)
                    {
                        packetData = pcap_next(pcapHandle, &header);

                        if (packetData == nullptr)
                        {
                            packetNumber++;
                            continue; // No packet captured, try again
                        }

                        NetworkPacket pDetails;
                        pDetails.networkInterface = networkInterfaces[i];
                        pDetails.packetNumber = packetNumber + 1;

                        // Buffer to store the formatted timestamp
                        char timestampBuffer[26];

                        if (ctime_s(timestampBuffer, sizeof(timestampBuffer), (const time_t*)&header.ts.tv_sec) == 0)
                        {
                            pDetails.timestamp = timestampBuffer;
                        }
                        else
                        {
                            pDetails.timestamp = "Error formatting timestamp";
                        }

                        // Extract packet data based on the type of interface
                        if (pDetails.networkInterface == "eth0")
                        {
                            // Assuming Ethernet frame size is at least 14 bytes (size of Ethernet header)
                            if (header.caplen >= 14)
                            {
                                const u_char* ethHeader = packetData;
                                const u_char* ipHeader = packetData + 14; // Skip Ethernet header
                                struct IpHeader* ip = (struct IpHeader*)ipHeader;

                                // Extract IP header fields
                                pDetails.ipHeader.version = (ip->version >> 4) & 0x0F;
                                pDetails.ipHeader.headerLength = (ip->headerLength & 0x0F) * 4;
                                pDetails.ipHeader.tos = ip->tos;
                                pDetails.ipHeader.totalLength = ntohs(ip->totalLength);
                                pDetails.ipHeader.identification = ntohs(ip->identification);
                                pDetails.ipHeader.flagsFragmentOffset = ntohs(ip->flagsFragmentOffset);
                                pDetails.ipHeader.ttl = ip->ttl;
                                pDetails.ipHeader.protocol = ip->protocol;
                                pDetails.ipHeader.headerChecksum = ntohs(ip->headerChecksum);

                                // Convert IP addresses to string representations
                                char sourceIpString[INET_ADDRSTRLEN];
                                char destinationIpString[INET_ADDRSTRLEN];

                                inet_ntop(AF_INET, &(ip->sourceIp), sourceIpString, INET_ADDRSTRLEN);
                                inet_ntop(AF_INET, &(ip->destinationIp), destinationIpString, INET_ADDRSTRLEN);

                                pDetails.ipHeader.sourceIp = sourceIpString;
                                pDetails.ipHeader.destinationIp = destinationIpString;

                                // You may also extract other fields depending on your requirements

                                // Assuming payload follows the IP header
                                const u_char* payload = packetData + 14 + (ip->headerLength * 4); // Skip Ethernet + IP header

                                // Copy payload data to the NetworkPacket
                                pDetails.applicationData.assign(payload, payload + header.caplen - 14 - (ip->headerLength * 4));

                                // Store the packet details in the shared vector
                                std::lock_guard<std::mutex> lock(mutex);
                                packetDetailsList[0].push_back(pDetails);
                            }
                        }
                        else if (pDetails.networkInterface == "wlan0")
                        {
                            // Assuming Wi-Fi frame size is at least 24 bytes (size of Wi-Fi header)
                            if (header.caplen >= 24)
                            {
                                const u_char* wifiHeader = packetData;

                                // Extract the frame control field (2 bytes)
                                uint16_t frameControl = wifiHeader[0] | (wifiHeader[1] << 8);

                                // Check if it's an IP packet (assuming it's an IPv4 packet)
                                if ((frameControl & 0x0F00) == 0x0800)
                                {
                                    const u_char* ipHeader = packetData + 24; // Skip Wi-Fi header
                                    struct IpHeader* ip = (struct IpHeader*)ipHeader;

                                    // Extract IP header fields
                                    pDetails.ipHeader.version = (ip->version >> 4) & 0x0F;
                                    pDetails.ipHeader.headerLength = (ip->headerLength & 0x0F) * 4;
                                    pDetails.ipHeader.tos = ip->tos;
                                    pDetails.ipHeader.totalLength = ntohs(ip->totalLength);
                                    pDetails.ipHeader.identification = ntohs(ip->identification);
                                    pDetails.ipHeader.flagsFragmentOffset = ntohs(ip->flagsFragmentOffset);
                                    pDetails.ipHeader.ttl = ip->ttl;
                                    pDetails.ipHeader.protocol = ip->protocol;
                                    pDetails.ipHeader.headerChecksum = ntohs(ip->headerChecksum);

                                    // Convert IP addresses to string representations
                                    char sourceIpString[INET_ADDRSTRLEN];
                                    char destinationIpString[INET_ADDRSTRLEN];

                                    inet_ntop(AF_INET, &(ip->sourceIp), sourceIpString, INET_ADDRSTRLEN);
                                    inet_ntop(AF_INET, &(ip->destinationIp), destinationIpString, INET_ADDRSTRLEN);

                                    pDetails.ipHeader.sourceIp = sourceIpString;
                                    pDetails.ipHeader.destinationIp = destinationIpString;

                                    // Assuming payload follows the IP header
                                    const u_char* payload = packetData + 20; // Skip Wi-Fi + IP header (assuming IP header is 20 bytes)

                                    // Calculate the payload length
                                    uint16_t payloadLength = header.caplen - 24 - 20; // Skip Wi-Fi header and IP header

                                    // Copy payload data to the NetworkPacket
                                    pDetails.applicationData.assign(payload, payload + payloadLength);

                                    // Store the packet details in the shared vector
                                    std::lock_guard<std::mutex> lock(mutex);
                                    packetDetailsList[1].push_back(pDetails);
                                }
                            }
                        }

                        else if (pDetails.networkInterface == "virtnet0")
                        {
                            // Logic for virtual network interface packet extraction
                            // You need to handle the format of virtual network packets here.

                            // Assuming the virtual network packet format includes an IP header
                            if (header.caplen >= sizeof(struct IpHeader))
                            {
                                const u_char* ipHeader = packetData;
                                struct IpHeader* ip = (struct IpHeader*)ipHeader;

                                // Extract IP header fields
                                pDetails.ipHeader.version = (ip->version >> 4) & 0x0F;
                                pDetails.ipHeader.headerLength = (ip->headerLength & 0x0F) * 4;
                                pDetails.ipHeader.tos = ip->tos;
                                pDetails.ipHeader.totalLength = ntohs(ip->totalLength);
                                pDetails.ipHeader.identification = ntohs(ip->identification);
                                pDetails.ipHeader.flagsFragmentOffset = ntohs(ip->flagsFragmentOffset);
                                pDetails.ipHeader.ttl = ip->ttl;
                                pDetails.ipHeader.protocol = ip->protocol;
                                pDetails.ipHeader.headerChecksum = ntohs(ip->headerChecksum);

                                // Convert IP addresses to string representations
                                char sourceIpString[INET_ADDRSTRLEN];
                                char destinationIpString[INET_ADDRSTRLEN];

                                inet_ntop(AF_INET, &(ip->sourceIp), sourceIpString, INET_ADDRSTRLEN);
                                inet_ntop(AF_INET, &(ip->destinationIp), destinationIpString, INET_ADDRSTRLEN);

                                pDetails.ipHeader.sourceIp = sourceIpString;
                                pDetails.ipHeader.destinationIp = destinationIpString;

                                // You may also need to handle the payload format for virtual network packets

                                // Assuming payload follows the IP header
                                const u_char* payload = packetData + sizeof(struct IpHeader); // Skip IP header

                                // Copy payload data to the NetworkPacket
                                pDetails.applicationData.assign(payload, payload + header.caplen - sizeof(struct IpHeader));

                                // Store the packet details in the shared vector
                                std::lock_guard<std::mutex> lock(mutex);
                                packetDetailsList[2].push_back(pDetails);
                            }
                        }

                        // You can add more packet processing logic

                        packetNumber++;
                    }

                    // Close the pcap session
                    pcap_close(pcapHandle);

                }
                catch (const std::exception& e)
                {
                    // Handle exceptions
                    std::lock_guard<std::mutex> lock(mutex);
                    std::cerr << "Error in thread" << ": " << e.what() << std::endl;
                }
                    });
            }

            // Wait for all threads to finish
            for (auto& thread : threads)
            {
                thread.join();
            }

            return packetDetailsList;
        }
        catch (const std::exception& e)
        {
            // Handle exceptions
            std::cerr << "Error: Exception occurred during packet collection: " << e.what() << std::endl;
        }

        // If an error occurs or the function fails, return an empty vector
        return {};
    }

    EndpointDataCollector::EndpointDataCollector(const std::string& ipAddress) : ipAddress(ipAddress) {}

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
            std::cerr << "Error: " << e.what() << std::endl;
            // Return an empty or error state EndpointData if needed
            return endpointData;  // You may define an error state in the struct
        }
    }

}