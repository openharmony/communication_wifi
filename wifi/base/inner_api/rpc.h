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

#ifndef OHOS_WIFI_RPC_H
#define OHOS_WIFI_RPC_H
#include <memory>
#include <functional>
#include "client.h"
#include "serial.h"
#include "wifi_logger.h"
#include "wifi_c_utils.h"
#include "wifi_common_def.h"

namespace OHOS {
namespace WIFI {
class Rpc {
public:
    using rpcMsgCallback = std::function<void(Context *context)>;
    Rpc() = default;
    virtual ~Rpc();
    int InitClient();
    void UnInitClient();
    void LockClient();
    void UnLockClient();
    int RpcClientCall();
    void ReadClientEnd();
    void RecvRpcMsgCallback(Context *context);
    static rpcMsgCallback GetRpcMsgCallback();
    virtual void OnDealRpcMsg(Context *context, int event) = 0;

protected:
    int WriteBegin(int type);
    int WriteEnd();
    int WriteFunc(const std::string &funcName);
    int WriteInt(int i);
    int WriteString(const std::string &str);
    int ReadInt(int *i);
    int ReadString(char *str, int count);

private:
    RpcClient *client = nullptr;
    static rpcMsgCallback recvRpcMsgCallback;
};
}  // namespace Wifi
}  // namespace OHOS
#endif