#ifndef DATA_H
#define DATA_H

#include <string>
#include <vector>
#include <iostream>

namespace DataCollection
{
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
        std::string networkInterface;
        int packetCount;

    public:
        PacketCollector(const std::string& networkInterface, int packetCount);
        std::string CollectData();
    };

    class FlowDataCollector
    {
    private:
        std::string networkInterface;
        int interval;

    public:
        FlowDataCollector(const std::string& networkInterface, int interval);
        std::string CollectData();
    };

    class EndpointDataCollector
    {
    private:
        std::vector<std::string> endpoints;
        std::string dataType;

    public:
        EndpointDataCollector(const std::vector<std::string>& endpoints, const std::string& dataType);
        std::string CollectData();
    };
}

#endif // DATA_H
