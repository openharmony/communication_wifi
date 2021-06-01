/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFILOCKINFO_H
#define OHOS_WIFILOCKINFO_H

#include <string>
#include "wifi_msg.h"
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
class WifiLockInfo {
public:
    /**
     * @Description Construct a new Wifi Lock object
     *
     * @param lockMode - lock type
     * @param tag - lock name, which is a unique identifier
     */
    WifiLockInfo(const WifiLockMode &lockType, const std::string &tag);

    /**
     * @Description Construct a new Default Wifi Lock object
     *
     */
    WifiLockInfo();

    /**
     * @Description Destroy the Wifi Lock Info object
     *
     */
    ~WifiLockInfo();

    /**
     * @Description Acquire the Wi-Fi lock.
     *
     * @param lockType - WifiLockMode object
     * @param tag - Lock tag
     * @return ErrCode - operation result
     */
    ErrCode Acquire();

    /**
     * @Description Release Wi-Fi lock.
     *
     * @param tag - Lock tag
     * @return ErrCode - operation result
     */
    ErrCode Release();

    /**
     * @Description Set wifi lock reference counted flag, whether used reference count mode
     *
     * @param refCounted - true / false
     */
    void SetReferenceCounted(bool refCounted);

    /**
     * @Description Check mHeld's value
     *
     * @return true
     * @return false
     */
    bool IsHeld();

    /**
     * @Description Set the Lock Type object
     *
     * @param lockType - lock type
     */
    void SetLockType(const WifiLockMode &lockType);

    /**
     * @Description Get the Lock Type object
     *
     * @return WifiLockMode - lock type
     */
    WifiLockMode GetLockType() const;

    /**
     * @Description Set the lock Tag object
     *
     * @param tag - lock tag info
     */
    void SetTag(const std::string &tag);

    /**
     * @Description Get the Lock Tag object
     *
     * @return std::string - lock tag info
     */
    std::string GetTag() const;

private:
    std::string mTag;
    int mRefCount;
    WifiLockMode mLockType;
    bool mRefCounted;
    bool mHeld;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
