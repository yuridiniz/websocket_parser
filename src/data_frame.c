// MIT License

// Copyright (c) 2021 Yuri Araújo Diniz Schmitz (yuri.araujod@gmail.com)

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "ws_parser.h"

static char * encode_fin(unsigned char * out) {
    *out |= (1 << 7);
    return out;
}

static char * encode_reserv(unsigned char * out) {
    *out |= (0 << 6);
    *out |= (0 << 5);
    *out |= (0 << 4);
    return out;
}

static char * encode_opcode(unsigned char * out, char val) {
    *out |= (val << 3);
    return ++out;
}

static char * encode_mask(unsigned char * out) {
    *out |= (0 << 7);
    return out;
}

static char * encode_payload_len(unsigned char * out, int len) {
    *out++ |= (len << 0);

    int next_sizes = (2 + 4 + 2);
    // memset(out, 0x1, 2);
    // memset(out+=2, 0x2, 4);
    // memset(out+=4, 0x3, 2);

    return &out[next_sizes];
}

static char * encode_payload_data(unsigned char * out, char * in, int in_len) {
    memcpy(out, in, in_len);
    out[in_len] = '\0';
    return &out[in_len];
}

static char * encode_mask_key(unsigned char * out) {
    int next_sizes = (2 + 2);
    // memset(out, 0x4, next_sizes);

    return &out[next_sizes];
}

int ws_decode(unsigned char * out, int out_len, char * in, int in_len) {
    
}

int ws_encode(unsigned char * out, int out_len, char * in, int in_len) {
    memset(out, 0x0, out_len);

    int encoded_len = 0;

    unsigned char * pointer = out;
    pointer = encode_fin(pointer);
    pointer = encode_reserv(pointer);
    pointer = encode_opcode(pointer, 0x1);
    pointer = encode_mask(pointer);
    pointer = encode_payload_len(pointer, in_len);
    pointer = encode_mask_key(pointer);
    pointer = encode_payload_data(pointer, in, in_len);

    return (pointer - out);
}