#include <iostream>
#include <string>
#include "captureDev.h"
#include <unistd.h>
#include <thread>

#define IPADDR "127.0.0.1"

int main(int argc, char* argv[])
{
    int default_port = 80;                      //默认监听80端口
    std::string default_protocol = "http";      //默认协议为http
    int optch = 0;
    while((optch = getopt(argc, argv, "p:t:")) != -1)
    {
        switch(optch)
        {
            case 'p':       //参数-p用于指定端口
                default_port = atoi(optarg);
                break;
            case 't':       //参数-t用于指定协议
                default_protocol = optarg;
                break;
            case '?':       //未知参数
                std::cerr << "Unknown option: " << (char)optopt << std::endl;
                return 1;
            default:        //若不指定参数，则使用默认值
                break;
        }
    }

    try
    {
        CaptureDev dev("127.0.0.1", default_protocol, default_port);
        dev.start();
        std::cout << "Capturing packets on " << IPADDR << " port " << default_port << " protocol " << default_protocol << std::endl;
        
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    

    return 0;
}