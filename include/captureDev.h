#ifndef __CAPTUREDEV_H__
#define __CAPTUREDEV_H__

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <PcapFilter.h>
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <HttpLayer.h>
#include <chrono>
#include <iomanip>

void printTime();

class CaptureDev
{
public:
    CaptureDev(const std::string& interface, const std::string& protocol, int port);
    ~CaptureDev();
    void start();
    void stop();
    void setFilter(const std::string& protocol, int port);
private:
    void capturePacket();
    void changeFilter();
    static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);  //pcpp回调函数重写
private:
    std::string interface_;
    int currentPort_;
    std::string currentProtocol_;
    pcpp::PcapLiveDevice* dev_;
    bool stopCapture_;
    bool updateFilter_;
};

#endif