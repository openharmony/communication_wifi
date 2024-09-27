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
#ifndef OHOS_WIFI_CONTROLLER_MANAGERS_TEMPLATE_H
#define OHOS_WIFI_CONTROLLER_MANAGERS_TEMPLATE_H
#include <memory>

namespace OHOS::Wifi {
template <class T>
class ManagerControl {
public:
    bool HasAnyManager()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return !managers.empty();
    }

    bool IdExist(int id)
    {
        return GetManager(id) != nullptr;
    }

    std::shared_ptr<T> GetFirstManager()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (managers.empty()) {
            return nullptr;
        }
        return managers.front();
    }

    std::shared_ptr<T> GetManager(int id)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (managers.empty()) {
            return nullptr;
        }
        for (auto iter = managers.begin(); iter != managers.end(); ++iter) {
            if ((*iter)->mid == id) {
                return *iter;
            }
        }
        return nullptr;
    }

    void StopManager(int id)
    {
        SendMessage(stopCmdId, id);
    }

    void StopAllManagers()
    {
        SendMessageToAll(stopCmdId);
    }

    void SendMessage(int cmd, int id)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (managers.empty()) {
            return;
        }
        for (auto iter = managers.begin(); iter != managers.end(); ++iter) {
            if ((*iter)->mid == id) {
                if (auto machine = (*iter)->GetMachine(); machine != nullptr) {
                    machine->SendMessage(cmd);
                }
                return;
            }
        }
    }

    void SendMessageToAll(int cmd)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (managers.empty()) {
            return;
        }
        for (auto iter = managers.begin(); iter != managers.end(); ++iter) {
            if (auto machine = (*iter)->GetMachine(); machine != nullptr) {
                machine->SendMessage(cmd);
            }
        }
    }

    void AddManager(std::shared_ptr<T> manager)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        managers.push_back(manager);
    }

    void RemoveManager(int id)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (managers.empty()) {
            return;
        }
        for (auto iter = managers.begin(); iter != managers.end(); ++iter) {
            if ((*iter)->mid == id) {
                managers.erase(iter);
                break;
            }
        }
    }

public:
    int stopCmdId;
    std::vector<std::shared_ptr<T>> managers {};
    mutable std::mutex mutex_;
};
}
#endif