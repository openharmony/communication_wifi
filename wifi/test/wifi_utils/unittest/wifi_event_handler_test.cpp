/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "wifi_event_handler_test.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
HWTEST_F(WifiEventHandlerTest, PostSyncTaskTest, TestSize.Level1)
{
    std::function<void()> callback = EventHandlerCallback;
    testEventHandler->PostSyncTask(callback);
}

HWTEST_F(WifiEventHandlerTest, PostAsyncTaskTest, TestSize.Level1)
{
    std::function<void()> callback = EventHandlerCallback;
    testEventHandler->PostAsyncTask(callback, 0);
}

HWTEST_F(WifiEventHandlerTest, PostAsyncTaskAndNameTest, TestSize.Level1)
{
    std::function<void()> callback = EventHandlerCallback;
    testEventHandler->PostAsyncTask(callback, "callback");
}

HWTEST_F(WifiEventHandlerTest, RemoveAsyncTaskTest, TestSize.Level1)
{
    testEventHandler->RemoveAsyncTask("callback");
}
}  // namespace Wifi
}  // namespace OHOS