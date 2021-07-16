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

#ifndef OHOS_FUNCTION_H
#define OHOS_FUNCTION_H

#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <arpa/inet.h>
#include <string>
#include <cstdio>

#include "dhcp_define.h"


namespace OHOS {
namespace Wifi {
class DhcpFunc {
public:
    DhcpFunc() {}
    ~DhcpFunc() {}

    static std::string IpToDot(unsigned int nIp);
    static unsigned int IPtoInt(const std::string& strIp);
    static bool Ip4StrConToInt(const std::string& strIp, uint32_t& uIp);
    static std::string Ip4IntConToStr(uint32_t uIp);
    static bool Ip6StrConToChar(const std::string& strIp, uint8_t chIp[], size_t uSize);
    static std::string Ip6CharConToStr(uint8_t chIp[], int size);
    static bool CheckIpStr(const std::string& strIp);
    static int GetLocalIp(const std::string ethInf, std::string& localIp);
    static int GetLocalMac(const std::string ethInf, std::string& ethMac);

    static bool IsExistFile(const std::string& filename);
    static bool CreateFile(const std::string& filename, const std::string& filedata);
    static bool RemoveFile(const std::string& filename);
    static bool AddFileLineData(const std::string& filename, const std::string& prevdata, const std::string& linedata);
    static bool DelFileLineData(const std::string& filename, const std::string& linedata);
    static bool ModifyFileLineData(const std::string& filename, const std::string& srcdata, const std::string& dstdata);
    static int FormatString(struct DhcpPacketResult &result);
    static int GetDhcpPacketResult(const std::string& filename, struct DhcpPacketResult &result);
    static int InitPidfile(const std::string& piddir, const std::string& pidfile);
    static pid_t GetPID(const std::string& pidfile);
};
}  // namespace Wifi
}  // namespace OHOS
#endif