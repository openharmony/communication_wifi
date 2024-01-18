/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_WIFI_DNS_CHECKER_H
#define OHOS_WIFI_DNS_CHECKER_H
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string>
#include <atomic>
namespace OHOS {
namespace Wifi {

class DnsChecker {
public:
    DnsChecker();
    ~DnsChecker();
    void Start(std::string priDns, std::string secondDns);
    void Stop();
    void StopDnsCheck();
    bool DoDnsCheck(std::string url, int timeoutMillis);
private:
    void formatHostAdress(char* hostAddress, const char* host);
    bool checkDnsValid(std::string host, std::string dnsAddress, int timeoutMillis);
    int recvDnsData(char* buff, int size, int timeout);
private:
    int dnsSocket;
    std::string primaryDnsAddress;
    std::string secondDnsAddress;
    bool socketCreated;
    std::atomic<bool> isRunning;
};
}
}
#endif
