#include "data.h"

#include <fstream>
#include <sstream>
#include <mutex>
#include <thread>

#include <pcap.h>

namespace DataCollection
{
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


    std::string PacketCollector::CollectData() 
    {
        try
        {
            // initialize a vector to hold packet details from each thread
            std::vector<std::string> packetDetailsList(networkInterfaces.size());

            // a mutex to protect shared data
            std::mutex mutex;

            // a vector to hold thread objects
            std::vector<std::thread> threads;

            // create a thread for each network interface
            for (size_t i = 0; i < networkInterfaces.size(); ++i)
            {
                threads.emplace_back([&, i]()
                {
                    try
                    {
                        // open the network interface for packet capture
                        char errbuf[PCAP_ERRBUF_SIZE];
                        pcap_t* pcapHandle = pcap_open_live(networkInterfaces[i].c_str(), BUFSIZ, 1, 1000, errbuf);

                        if (pcapHandle == nullptr)
                        {
                            std::cerr << "Error: Failed to open network interface: " << errbuf << std::endl;
                            return;
                        }

                        //capture packets
                        struct pcap_pkthdr header;
                        const u_char* packet;
                        int packetNumber = 0;
                        std::stringstream packetDetails;

                        while (packetNumber < packetCount)
                        {
                            packet = pcap_next(pcapHandle, &header);

                            if (packet == nullptr)
                            {
                                continue; // no packet captured , try agaiin
                            }

                            // buffer to store the formatted timestamp
                            char timestampBuffer[26];

                            // process the captured packet e.g print packet details
                            packetDetails << "Interface " << networkInterfaces[i] << "- Packet" << packetNumber + 1 << ":\n";
                            packetDetails << " - Length: " << header.len << "bytes\n";
                            packetDetails << " - Captured Length: " << header.caplen << "bytes\n";

                            if (ctime_s(timestampBuffer, sizeof(timestampBuffer), (const time_t*)&header.ts.tv_sec) == 0)
                            {
                                packetDetails << " - Timestamp: " << timestampBuffer;
                            }
                            else
                            {
                                packetDetails << " - Timestamp: Error formatting timestamp";
                            }

                            //you can add more packet processing logic

                            packetNumber++;
                        }

                        // close the pcap session
                        pcap_close(pcapHandle);

                        // store the packet details in the shared vector
                        std::lock_guard<std::mutex> lock(mutex);
                        packetDetailsList[i] = packetDetails.str();
                    }

                    catch (const std::exception& e)
                    {
                        // handle exceptions
                        std::cerr << "Error in thread" << ": " << e.what() << std::endl;
                    }
                });
            }

            // wait for all threads to finish
            for (auto& thread : threads)
            {
                thread.join();
            }

            // combine packet details from all threads
            std::stringstream combinedPacketDetails;
            for (const auto& details : packetDetailsList)
            {
                combinedPacketDetails << details << "\n";
            }

            return combinedPacketDetails.str();
        }
        catch (const std::exception e)
        {
            //handle exceptions
            std::cerr << "Error: Exception occurred during packet collection: " << e.what() << std::endl;
            return "Error: Packet collection failed";
        }
    }


}
