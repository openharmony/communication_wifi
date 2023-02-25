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

Context *SerialTest::ctx = nullptr;

HWTEST_F(SerialTest, SerialOneTest, TestSize.Level1)
{
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

HWTEST_F(SerialTest, SerialTwoTest, TestSize.Level1)
{
    ctx->oneProcess = ctx->szWrite;
    ctx->nSize = ctx->wEnd;

    EXPECT_TRUE(strncmp(ctx->oneProcess, "N\t", 2) == 0);
    ctx->nPos = 2;
    char str[1024] = {0};
    ASSERT_EQ(ReadFunc(ctx, str, 1024), 0);
    ASSERT_EQ(ReadFunc(test, str, 1024), -1);

    ctx->nSize = ctx->nPos;
    ASSERT_EQ(ReadFunc(ctx, str, 1024), -1);

    EXPECT_TRUE(strcmp(str, "SerialTest") == 0);
    int i = 0;
    ctx->nSize = ctx->wEnd;
    ASSERT_EQ(ReadInt(test, &i), -1);
    ASSERT_EQ(ReadInt(ctx, &i), 0);

    EXPECT_TRUE(i == 100);
    long l = 0;
    ASSERT_EQ(ReadLong(test, &l), -1);
    ASSERT_EQ(ReadLong(ctx, &l), 0);
    EXPECT_TRUE(l == 1234567890L);
    int64_t t = 0;
    ASSERT_EQ(ReadInt64(test, &t), -1);
    ASSERT_EQ(ReadInt64(ctx, &t), 0);
    EXPECT_TRUE(t == 12345678909832323LL);
    double d = 0.0;
    ASSERT_EQ(ReadDouble(test, &d), -1);
    ASSERT_EQ(ReadDouble(ctx, &d), 0);
    EXPECT_TRUE(d - 3.14159 < 0.000001 && d - 3.14159 > -0.000001);
    char c = ' ';
    ASSERT_EQ(ReadChar(test, &c), -1);
    ASSERT_EQ(ReadChar(ctx, &c), 0);
    EXPECT_TRUE(c == 'a');
    ASSERT_EQ(ReadStr(test, str, 1024), -1);
    ASSERT_EQ(ReadStr(ctx, str, 1024), 0);
    EXPECT_TRUE(strcmp(str, "Hello, world") == 0);
    int count = strlen("2c:f0:xx:xx:xx:be");
    ASSERT_EQ(ReadUStr(test, (unsigned char *)str, count + 1), -1);
    ASSERT_EQ(ReadUStr(ctx, (unsigned char *)str, count + 1), 0);
    EXPECT_TRUE(strcmp(str, "2c:f0:xx:xx:xx:be") == 0);
    EXPECT_TRUE(strncmp(ctx->oneProcess + ctx->nPos, "$$$$$$", 6) == 0);
}
}  // namespace Wifi
}  // namespace OHOS