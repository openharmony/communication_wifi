/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "scan_ashmem_parcel.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_SCAN_LABEL("ScanAshmemParcel");
namespace OHOS {
namespace Wifi {

bool ScanAshmemParcel::Marshalling(Parcel &parcel) const
{
    MessageParcel &msgParcel = static_cast<MessageParcel &>(parcel);

    if (ashmem_ == nullptr) {
        return false;
    }

    if (!msgParcel.WriteAshmem(ashmem_)) {
        return false;
    }

    WIFI_LOGI("ScanAshmemParcel Marshalling: success");
    return true;
}

ScanAshmemParcel *ScanAshmemParcel::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<ScanAshmemParcel> ashmemParcelPtr = std::make_unique<ScanAshmemParcel>();
    if (ashmemParcelPtr == nullptr) {
        return nullptr;
    }

    MessageParcel *msgParcel = static_cast<MessageParcel *>(&parcel);
    if (msgParcel == nullptr) {
        return nullptr;
    }

    sptr<Ashmem> ashmem = msgParcel->ReadAshmem();
    if (ashmem == nullptr) {
        WIFI_LOGE("ScanAshmemParcel Unmarshalling: ReadAshmem failed");
        return nullptr;
    }

    ashmemParcelPtr->ashmem_ = ashmem;
    WIFI_LOGI("ScanAshmemParcel Unmarshalling: success");

    return ashmemParcelPtr.release();
}
}  // namespace Wifi
}  // namespace OHOS
