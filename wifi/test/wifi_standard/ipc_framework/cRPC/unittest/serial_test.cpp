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

#include "serial_test.h"
#include "serial.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
HWTEST_F(SerialTest, SerialOneTest, TestSize.Level1)
{
    ctx = CreateContext(1024);
    WriteBegin(ctx, 0);
    ASSERT_EQ(WriteBegin(test, 0), -1);

    WriteFunc(ctx, "SerialTest");
    ASSERT_EQ(WriteFunc(test, "SerialTest"), -1);

    WriteInt(ctx, 100);
    ASSERT_EQ(WriteInt(test, 100), -1);

    WriteLong(ctx, 1234567890L);
    ASSERT_EQ(WriteLong(test, 1234567890L), -1);

    WriteInt64(ctx, 12345678909832323LL);
    ASSERT_EQ(WriteInt64(test, 12345678909832323LL), -1);

    WriteDouble(ctx, 3.14159);
    ASSERT_EQ(WriteDouble(test, 3.14159), -1);

    WriteChar(ctx, 'a');
    ASSERT_EQ(WriteChar(test, 'a'), -1);

    WriteStr(ctx, "Hello, world");
    ASSERT_EQ(WriteStr(test, "Hello, world"), -1);

    int count = strlen("2c:f0:xx:xx:xx:be");
    WriteUStr(ctx, (const unsigned char *)"2c:f0:xx:xx:xx:be", count);
    ASSERT_EQ(WriteUStr(test, (const unsigned char *)"2c:f0:xx:xx:xx:be", count), -1);

    WriteEnd(ctx);
    ASSERT_EQ(WriteEnd(test), -1);
}
}  // namespace Wifi
}  // namespace OHOS