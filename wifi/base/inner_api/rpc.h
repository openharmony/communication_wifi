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
#include <thread>
#include "client.h"

namespace OHOS {
namespace Wifi {
class Rpc {
public:
    Rpc() = default;
    virtual ~Rpc();
    int InitClient(const std::string &sockPath);
    void UnInitClient();
    void LockClient();
    void UnLockClient();
    int RpcClientCall();
    void ReadClientEnd();
    virtual void OnDealRpcMsg(Context *context) = 0;

protected:
    int WriteBegin(int type);
    int WriteEnd();
    int WriteFunc(const std::string &funcName);
    int WriteInt(int i);
    int WriteString(const std::string &str);
    int ReadInt(int *i);
    int ReadInt(Context *context, int *i);
    int ReadString(char *str, int count);
    int ReadString(Context *context, char *str, int count);

private:
    void RpcClientDealReadMsg(RpcClient *client, char *buff);
    char *RpcClientReadMsg(RpcClient *client);
    void RpcClientThreadDeal();
    RpcClient *CreateRpcClient(const std::string &path);

private:
    RpcClient *client = nullptr;
    std::thread rpcClientThread;
};
}  // namespace Wifi
}  // namespace OHOS
#endif