/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 
#include "mock_serial.h"
 
int WriteBegin(Context *context, int type)
{
    return 0;
}
 
int WriteFunc(Context *context, const char *funcName)
{
    return 0;
}
 
int WriteInt(Context *context, int iData)
{
    return 0;
}
 
int WriteLong(Context *context, long lData)
{
    return 0;
}
 
int WriteInt64(Context *context, int64_t iData)
{
    return 0;
}
 
int WriteDouble(Context *context, double dData)
{
    return 0;
}
 
int WriteChar(Context *context, char cData)
{
    return 0;
}
 
int WriteStr(Context *context, const char *pStr)
{
    return 0;
}
 
int WriteUStr(Context *context, const unsigned char *uStr, unsigned int len)
{
    return 0;
}
 
int WriteEnd(Context *context)
{
    return 0;
}
 
int ReadFunc(Context *context, char *funcName, int count)
{
    return 0;
}
 
int ReadInt(Context *context, int *iData)
{
    return 0;
}
 
int ReadLong(Context *context, long *pLong)
{
    return 0;
}
 
int ReadInt64(Context *context, int64_t *pInt64)
{
    return 0;
}
 
int ReadDouble(Context *context, double *dData)
{
    return 0;
}
 
int ReadChar(Context *context, char *cData)
{
    return 0;
}
 
int ReadStr(Context *context, char *str, int count)
{
    return 0;
}
 
int ReadUStr(Context *context, unsigned char *uStr, int count)
{
    return 0;
}