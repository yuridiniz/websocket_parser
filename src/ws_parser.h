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

#ifndef WS_PARSER_H
#define WS_PARSER_H

#ifdef __cplusplus
extern "C"{
#endif 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WS_MAGIC_STR "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAGIC_LEN 36

#define WS_RESPONSE_101_HEADER "HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: "

#define BUFFER_CLEAR(buf) buf[0] = '\0'
#define BUFFER_SIZE(pointer, buf) (pointer - buf)

typedef struct ws_handshake_request {
    char * method;
    char * path;
    char * http_version;
    char * host;
    char * upgrade;
    char * connection;
    char * sec_websocket_key;
    char * sec_websocket_version;
} ws_handshake_request_t;


typedef struct ws_handshake_response {
    char * sec_websocket_accept;
    char * data;
} ws_handshake_response_t;


char * ws_strncat(char * dest, char * src, int len);
char * ws_strcat(char * dest, char * src);

ws_handshake_request_t * ws_parser_request(char * data, int data_len);
ws_handshake_response_t * ws_format_response(ws_handshake_request_t * self);

int ws_decode(unsigned char * out, int out_len, char * in, int in_len);
int ws_encode(unsigned char * out, int out_len, char * in, int in_len);

void ws_free_req(ws_handshake_request_t *);
void ws_free_resp(ws_handshake_response_t *);


#ifdef __cplusplus
}
#endif
#endif