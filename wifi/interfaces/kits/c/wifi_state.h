/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef WIFI_STATE_C_H
#define WIFI_STATE_C_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* state is unknown */
    STATE_UNKNOWN = -1,

    /* wifi is closed */
    STATE_INACTIVE = 0,

    /* wifi is opened */
    STATE_ACTIVATED = 1,

    /* wifi is opening */
    STATE_ACTIVATING = 2,

    /* wifi is closing */
    STATE_DEACTIVATING = 3,

    /* wifi is entering semi active */
    STATE_SEMI_ACTIVATING = 4,

    /* wifi is semi active */
    STATE_SEMI_ACTIVE = 5
} WifiDetailState;

#ifdef __cplusplus
}
#endif

#endif // WIFI_STATE_C_H
/** @} */
