/*
*Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
*/

#ifndef AP_NETWORK_NETWORK_MONITOR_H
#define AP_NETWORK_NETWORK_MONITOR_H

#include <mutex>
#include <vector>

namespace OHOS {
namespace Wifi {
class ApNetworkMonitor {
public:
    ApNetworkMonitor() = default;
    ~ApNetworkMonitor() = default;
    static ApNetworkMonitor &GetInstance();
    void DealApNetworkCapabilitiesChanged();
};

} //namespace Wifi
} //namespace OHOS

#endif //AP_NETWORK_NETWORK_MONITOR_H