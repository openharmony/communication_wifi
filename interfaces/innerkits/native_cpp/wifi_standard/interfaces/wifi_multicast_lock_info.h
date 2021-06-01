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

#ifndef OHOS_WIFIMULTICASTLOCKINFO_H
#define OHOS_WIFIMULTICASTLOCKINFO_H

#include <string>
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
class WifiMulticastLockInfo {
public:
    /**
     * @Description Construct a new Wifi Multicast Lock Info object
     *
     * @param tag - lock tag info
     */
    WifiMulticastLockInfo(const std::string &tag);

    /**
     * @Description Construct a new Default Wifi Multicast Lock Info object
     *
     */
    WifiMulticastLockInfo();

    /**
     * @Description Destroy the Wifi Multicast Lock Info object
     *
     */
    ~WifiMulticastLockInfo();

    /**
     * @Description Acquire multicast lock.
     *
     * @param tag - Lock tag
     * @return ErrCode - operation result
     */
    ErrCode Acquire();

    /**
     * @Description Release multicast lock.
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
     * @Description Set the Tag object
     *
     * @param tag - lock tag info
     */
    void SetTag(const std::string &tag);

    /**
     * @Description Get the Tag object
     *
     * @return std::string - lock tag info
     */
    std::string GetTag() const;

private:
    std::string mTag;
    int mRefCount;
    bool mRefCounted;
    bool mHeld;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
