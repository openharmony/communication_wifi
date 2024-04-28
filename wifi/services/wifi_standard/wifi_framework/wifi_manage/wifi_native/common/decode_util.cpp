/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "decode_util.h"

constexpr int HEX2NUM_CONS = 10;
constexpr int POS_OFFSET = 2;
constexpr int HEX2BYTE_CONS = 4;
constexpr int OCTAL_CONS = 8;

int Hex2num(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + HEX2NUM_CONS;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + HEX2NUM_CONS;
    }
    return -1;
}

int Hex2byte(const char *hex)
{
    int a;
    int b;
    a = Hex2num(*hex++);
    if (a < 0) {
        return -1;
    }
    b = Hex2num(*hex++);
    if (b < 0) {
        return -1;
    }
    return (a << HEX2BYTE_CONS) | b;
}

void DealDigital(u8 *buf, const char **pos, size_t *len)
{
    int val;
    switch (**pos) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
            val = **pos++ - '0';
            if (**pos >= '0' && **pos <= '7') {
                val = val * OCTAL_CONS + (**pos++ - '0');
            }
            if (**pos >= '0' && **pos <= '7') {
                val = val * OCTAL_CONS + (**pos++ - '0');
            }
            buf[(*len)++] = val;
            return;
        default:
            return;
    }
}

void DealSymbol(u8 *buf, const char **pos, size_t *len)
{
    int val;
    switch (**pos) {
        case '\\':
            buf[(*len)++] = '\\';
            (*pos)++;
            return;
        case '"':
            buf[(*len)++] = '"';
            (*pos)++;
            return;
        case 'n':
            buf[(*len)++] = '\n';
            (*pos)++;
            return;
        case 'r':
            buf[(*len)++] = '\r';
            (*pos)++;
            return;
        case 't':
            buf[(*len)++] = '\t';
            (*pos)++;
            return;
        case 'e':
            buf[(*len)++] = '\033';
            (*pos)++;
            return;
        case 'x':
            (*pos)++;
            val = Hex2byte(*pos);
            if (val < 0) {
                val = Hex2num(**pos);
                if (val < 0) {
                    return;
                }
                buf[(*len)++] = val;
                (*pos)++;
            } else {
                buf[(*len)++] = val;
                (*pos) += POS_OFFSET;
            }
            return;
        default:
            DealDigital(buf, pos, len);
            return;
    }
}

size_t PrintfDecode(u8 *buf, size_t maxlen, const char *str)
{
    const char *pos = str;
    size_t len = 0;

    while (*pos) {
        if (len + 1 >= maxlen) {
            break;
        }
        switch (*pos) {
            case '\\':
                pos++;
                DealSymbol(buf, &pos, &len);
                break;
            default:
                buf[len++] = *pos++;
                break;
        }
    }
    if (maxlen > len) {
        buf[len] = '\0';
    }
    return len;
}
