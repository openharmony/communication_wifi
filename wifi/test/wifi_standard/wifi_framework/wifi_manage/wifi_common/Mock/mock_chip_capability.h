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

#ifndef OHOS_MOCK_CHIP_CAPABILITY_H
#define OHOS_MOCK_CHIP_CAPABILITY_H

#include <gmock/gmock.h>

namespace OHOS {
namespace Wifi {
class MockChipCapability {
public:
    MockChipCapability() = default;
    virtual ~MockChipCapability() = default;

    virtual bool InitializeChipCapability() = 0;
    virtual bool IsSupportDbdc(void) = 0;
    virtual bool IsSupportCsa(void) = 0;
    virtual bool IsSupportRadarDetect(void) = 0;
    virtual bool IsSupportDfsChannel(void) = 0;
    virtual bool IsSupportIndoorChannel(void) = 0;
};

class ChipCapability : public MockChipCapability {
public:
    ChipCapability() = default;
    ~ChipCapability() = default;
    static ChipCapability &GetInstance(void);
    MOCK_METHOD0(InitializeChipCapability, bool());
    MOCK_METHOD0(IsSupportDbdc, bool());
    MOCK_METHOD0(IsSupportCsa, bool());
    MOCK_METHOD0(IsSupportRadarDetect, bool());
    MOCK_METHOD0(IsSupportDfsChannel, bool());
    MOCK_METHOD0(IsSupportIndoorChannel, bool());
};
}  // namespace Wifi
} //  namespace OHOS
#endif