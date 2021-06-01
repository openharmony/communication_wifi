/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_IF_CONFIG_H
#define OHOS_WIFI_IF_CONFIG_H

#include <memory>
#include "wifi_log.h"
#include "sta_define.h"

namespace OHOS {
namespace Wifi {
class IfConfig {
public:
    IfConfig();
    ~IfConfig();

    static IfConfig &GetInstance();

    int SetIfAddr(const DhcpResult &dhcpResult) const;
    void SetNetDns(std::string ifName, std::string dns1, std::string dns2) const;
    void FlushIpAddr(std::string ifName, int ipType) const;
    void AddIpAddr(std::string ifName, std::string ipAddr, std::string mask, int ipType) const;
    void AddIfRoute(std::string ifName, std::string ipAddr, std::string mask, std::string gateWay, int ipType) const;
    void AddIpv4Route(std::string ifName, std::string ipAddr, std::string mask, std::string gateWay) const;
    void AddIpv6Route(std::string ifName, std::string ipAddr, std::string mask, std::string gateWay) const;
    void SetProxy(bool isAuto, std::string proxy, std::string port, std::string noProxys, std::string pac) const;
    bool ExecCommand(const std::vector<std::string> &vecCommandArg) const;

private:
    static std::unique_ptr<IfConfig> g_ifConfig;
};
}  // namespace Wifi
}  // namespace OHOS
#endif