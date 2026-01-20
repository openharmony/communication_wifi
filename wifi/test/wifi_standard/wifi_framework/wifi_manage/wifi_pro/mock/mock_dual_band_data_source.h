/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_TEST_MOCK_DUAL_BAND_DATA_SOURCE_H
#define OHOS_WIFI_TEST_MOCK_DUAL_BAND_DATA_SOURCE_H
#include "i_dual_band_data_source.h"

namespace OHOS {
namespace Wifi {
class MockDualBandDataSource : public IDualBandDataSource {
public:
    ~MockDualBandDataSource()
    {}
    bool Connection() override
    {
        return true;
    }
    bool QueryApInfo(std::string &bssid, SwitchableApInfo &apInfo) override
    {
        return true;
    }
    bool QueryRelationInfo(std::string &bssid, std::vector<RelationInfo> &relationInfos) override
    {
        return true;
    }
    bool DeleteAll(std::unordered_set<std::string> &bssids) override
    {
        return true;
    }
    bool SaveApInfo(SwitchableApInfo &apInfo) override
    {
        return true;
    }
    void SaveApInfos(std::vector<SwitchableApInfo> &apInfos) override
    {}
    void SaveRelationInfos(std::vector<RelationInfo> &relationInfos) override
    {}
    bool QueryApInfos(std::unordered_set<std::string> &bssidSet, std::vector<SwitchableApInfo> &apInfos) override
    {
        return true;
    }
    bool RemoveDuplicateDatas() override
    {
        return true;
    }
};
}
}
#endif