/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#ifndef OHOS_MOCK_HAL_DEVICE_MANAGE_H
#define OHOS_MOCK_HAL_DEVICE_MANAGE_H
 
#include <string>
#include <vector>
 
namespace OHOS {
namespace Wifi {
 
class MockHalDeviceManager {
public:
 
    virtual ~MockHalDeviceManager() = default;
    virtual bool GetFrequenciesByBand(const std::string &ifaceName, int32_t band, std::vector<int> &frequencies);
};
 
class HalDeviceManager : public MockHalDeviceManager {
public:
    HalDeviceManager();
 
    ~HalDeviceManager() override;
    /**
     * @Description get instance of HalDeviceManager
     *
     * @param
     * @return HalDeviceManager
     */
    static HalDeviceManager &GetInstance();
    bool GetFrequenciesByBand(const std::string &ifaceName, int32_t band, std::vector<int> &frequencies) override;
};
}
}
#endif