/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_MANAGER_CLI_H
#define OHOS_WIFI_MANAGER_CLI_H

#include <string>

#include "cJSON.h"

namespace OHOS {
namespace WifiCli {

void OutputSuccessJson(cJSON* data);
void OutputErrorJson(const std::string& code, const std::string& message, const std::string& suggestion = "");
int RunCommand(int argc, char** argv);

} // namespace WifiCli
} // namespace OHOS

#endif // OHOS_WIFI_MANAGER_CLI_H
