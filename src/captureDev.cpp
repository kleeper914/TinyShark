#include "captureDev.h"

CaptureDev::CaptureDev(const std::string& interface="127.0.0.1", const std::string& protocol="http", int port=80)
    : interface_(interface),
    dev_(nullptr),
    currentPort_(80),
    currentProtocol_("http"),
    stopCapture_(false),
    updateFilter_(false)
{
    dev_ = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interface_);
    if(dev_ == nullptr)
    {
        throw std::runtime_error("Cannot find device with IP address of " + interface_);
    }
    if(!dev_->open())
    {
        throw std::runtime_error("Cannot open device");
    }
    
}

CaptureDev::~CaptureDev()
{
    stop();
    if(dev_ != nullptr)
    {
        dev_->close();
    }
}

void CaptureDev::start()
{
    stopCapture_ = false;
    captureThread_ = std::thread(&CaptureDev::capturePacket, this);
}

void CaptureDev::stop()
{
    stopCapture_ = true;
    if(captureThread_.joinable())
    {
        captureThread_.join();
    }
}

void CaptureDev::capturePacket()
{
    while(!stopCapture_)
    {
        if(updateFilter_)   //如果需要更新过滤器
        {
            dev_->stopCapture();
            pcpp::ProtoFilter* proto_filter = nullptr;
            if(currentProtocol_ == "tcp")
            {
                proto_filter = new pcpp::ProtoFilter(pcpp::TCP);
            }
            else if(currentProtocol_ == "udp")
            {
                proto_filter = new pcpp::ProtoFilter(pcpp::UDP);
            }
            else if(currentProtocol_ == "http")
            {
                proto_filter = new pcpp::ProtoFilter(pcpp::HTTP);
            }

            pcpp::PortFilter port_filter = pcpp::PortFilter(currentPort_, pcpp::SRC_OR_DST);
            pcpp::AndFilter filter;
            filter.addFilter(proto_filter);
            filter.addFilter(&port_filter);

            dev_->setFilter(filter);
            delete proto_filter;
            updateFilter_ = false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100)); //每隔100毫秒抓包
        dev_->startCapture(onPacketArrives, nullptr);
    }
}

void CaptureDev::setFilter(const std::string& protocol, int port)
{
    currentPort_ = port;
    currentProtocol_ = protocol;
    updateFilter_ = true;
}

void CaptureDev::onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    pcpp::Packet parsedPacket(packet);
    //解析以太网层
    pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if(ethernetLayer != nullptr)
    {
        std::cout << "Ethernet Layer:" << std::endl;
        std::cout << "Source MAC: " << ethernetLayer->getSourceMac() << std::endl;
        std::cout << "Destination MAC: " << ethernetLayer->getDestMac() << std::endl;
    }
    //解析IP层
    //IPV4
    pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if(ipv4Layer != nullptr)
    {
        std::cout << "IPv4 Layer:" << std::endl;
        std::cout << "Source IP: " << ipv4Layer->getSrcIPv4Address() << std::endl;
        std::cout << "Destination IP: " << ipv4Layer->getDstIPv4Address() << std::endl;
    }
    //IPV6
    pcpp::IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
    if(ipv6Layer != nullptr)
    {
        std::cout << "IPv6 Layer:" << std::endl;
        std::cout << "Source IP: " << ipv6Layer->getSrcIPv6Address() << std::endl;
        std::cout << "Destination IP: " << ipv6Layer->getDstIPv6Address() << std::endl;
    }
    //解析传输层
    //TCP
    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    if(tcpLayer != nullptr)
    {
        std::cout << "TCP Layer:" << std::endl;
        std::cout << "Source Port: " << tcpLayer->getSrcPort() << std::endl;
        std::cout << "Destination Port: " << tcpLayer->getDstPort() << std::endl;
    }
    //UDP
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if(udpLayer != nullptr)
    {
        std::cout << "UDP Layer:" << std::endl;
        std::cout << "Source Port: " << udpLayer->getSrcPort() << std::endl;
        std::cout << "Destination Port: " << udpLayer->getDstPort() << std::endl;
    }
    //解析应用层
    //HTTP
    pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
    if(httpRequestLayer != nullptr)
    {
        std::cout << "HTTP Request Layer:" << std::endl;
        std::cout << "Method: " << httpRequestLayer->getFirstLine()->getMethod() << std::endl;
        std::cout << "Url: " << httpRequestLayer->getFirstLine()->getUri() << std::endl;
        std::cout << "Version: " << httpRequestLayer->getFirstLine()->getVersion() << std::endl;
        //获取HTTP头部
        std::cout << "Header:" << std::endl;
        pcpp::HeaderField* field = httpRequestLayer->getFirstField();
        while(field != nullptr)
        {
            std::cout << field->getFieldName() << ": " << field->getFieldValue() << std::endl;
            field = httpRequestLayer->getNextField(field);
        }
    }
    pcpp::HttpResponseLayer* httpResponseLayer = parsedPacket.getLayerOfType<pcpp::HttpResponseLayer>();
    if(httpResponseLayer != nullptr)
    {
        std::cout << "HTTP Response Layer:" << std::endl;
        std::cout << "Status Code: " << httpResponseLayer->getFirstLine()->getStatusCode() << std::endl;
        std::cout << "Version: " << httpResponseLayer->getFirstLine()->getVersion() << std::endl;
        //获取HTTP头部
        std::cout << "Header:" << std::endl;
        pcpp::HeaderField* field = httpResponseLayer->getFirstField();
        while(field != nullptr)
        {
            std::cout << field->getFieldName() << ": " << field->getFieldValue() << std::endl;
            field = httpResponseLayer->getNextField(field);
        }
    }

    std::cout << "----------------------------------------" << std::endl;
}