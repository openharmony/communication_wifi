/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HOSTAPDTYPES_H
#define HOSTAPDTYPES_H

#include <stdbool.h>
#include <stdint.h>

#ifndef HDI_BUFF_MAX_SIZE
#define HDI_BUFF_MAX_SIZE (1024 * 200)
#endif

#ifndef HDI_CHECK_VALUE_RETURN
#define HDI_CHECK_VALUE_RETURN(lv, compare, rv, ret) do { \
    if ((lv) compare (rv)) { \
        return ret; \
    } \
} while (false)
#endif

#ifndef HDI_CHECK_VALUE_RET_GOTO
#define HDI_CHECK_VALUE_RET_GOTO(lv, compare, rv, ret, value, table) do { \
    if ((lv) compare (rv)) { \
        ret = value; \
        goto table; \
    } \
} while (false)
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HdfSBuf;

struct HdiApCbParm {
    char* content;
    int32_t id;
};

bool HdiApCbParmBlockMarshalling(struct HdfSBuf *data, const struct HdiApCbParm *dataBlock);

bool HdiApCbParmBlockUnmarshalling(struct HdfSBuf *data, struct HdiApCbParm *dataBlock);

void HdiApCbParmFree(struct HdiApCbParm *dataBlock, bool freeSelf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // HOSTAPDTYPES_H