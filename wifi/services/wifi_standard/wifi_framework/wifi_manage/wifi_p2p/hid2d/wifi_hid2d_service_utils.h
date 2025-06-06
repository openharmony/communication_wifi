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

#ifndef OHOS_WIFI_HID2D_SERVICE_UTILS_H
#define OHOS_WIFI_HID2D_SERVICE_UTILS_H

#include <string>
#include <list>
#include <map>
#include <atomic>

namespace OHOS {
namespace Wifi {
class IpPool {
public:
    static bool InitIpPool(const std::string& serverIp);
    static std::string GetIp(const std::string& gcMac);
    static void ReleaseIp(const std::string& gcMac);
    static void ReleaseIpPool();

private:
    static bool IsValidIp(const std::string& ip);

    static std::list<std::string> ipList;
    static std::map<std::string, std::string> mapGcMacToAllocIp;
    static constexpr int HID2D_IPPOOL_START = 3;
    static constexpr int HID2D_IPPOOL_END = 75;
};

class SharedLinkManager {
public:
    static void SetGroupUid(int callingUid);
    static void GetGroupUid(int &callingUid);
    static void IncreaseSharedLink();
    static void IncreaseSharedLink(int callingUid);
    static void DecreaseSharedLink(int callingUid);
    static void ClearSharedLinkCount();
    static int GetSharedLinkCount();
    static void ClearUidCount(int uid);
private:
    static void PrintMapInfo(void);

private:
    static std::map<int, int> sharedLinkCountMap;
    static int firstGroupUid;
};
}  // namespace Wifi
}  // namespace OHOS
#endif