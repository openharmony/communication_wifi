/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
#ifndef OHOS_MOCK_BLOCK_CONNECT_SERVICE_H
#define OHOS_MOCK_BLOCK_CONNECT_SERVICE_H

#include <gmock/gmock.h>
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
class MockBlockConnectService {
public:
  virtual bool EnableNetworkSelectStatus(int targetNetworkId) = 0;
  virtual bool UpdateNetworkSelectStatus(int targetNetworkId, DisabledReason disableReason) = 0;
  virtual bool UpdateAllNetworkSelectStatus() = 0;
};

class BlockConnectService : public MockBlockConnectService {
public:
    BlockConnectService() = default;
    ~BlockConnectService() = default;
    static BlockConnectService &GetInstance();
    MOCK_METHOD1(EnableNetworkSelectStatus, bool(int targetNetworkId));
    MOCK_METHOD2(UpdateNetworkSelectStatus, bool(int targetNetworkId, DisabledReason disableReason));
    MOCK_METHOD0(UpdateAllNetworkSelectStatus, bool());
};
}  // namespace OHOS
}  // namespace Wifi
#endif