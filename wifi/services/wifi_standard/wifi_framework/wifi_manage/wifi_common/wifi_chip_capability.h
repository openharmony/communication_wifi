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

#ifndef OHOS_WIFI_CHIP_CAPABILITY_H
#define OHOS_WIFI_CHIP_CAPABILITY_H

#include <string>

namespace OHOS {
namespace Wifi {
class ChipCapability {
public:
    ChipCapability();
    virtual ~ChipCapability();
    bool InitializeChipCapability();
    static ChipCapability& GetInstance();

    bool IsSupportDbdc(void);
    bool IsSupportCsa(void);
    bool IsSupportRadarDetect(void);
    bool IsSupportDfsChannel(void);
    bool IsSupportIndoorChannel(void);

private:
    std::string ToString(void);

private:
    bool m_isInitialized;
    bool m_isSupportDbdc;
    bool m_isSupportCsa;
    bool m_isSupportRadarDetect;
    bool m_isSupportDfsChannel;
    bool m_isSupportIndoorChannel;
};
}  // namespace Wifi
}  // namespace OHOS
#endif