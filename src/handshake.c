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

#include "handshake.h"
#include "sha1/sha1.h"
#include "b64/b64.h"

#define _WS_FREE(arg) if(arg != NULL) free(arg)   

#define BUFFER_CLEAR(buf) buf[0] = '\0'
#define BUFFER_SIZE(pointer, buf) (pointer - buf)

char * ws_strncat(char * dest, char * src, int len) {
    memcpy(dest, src, len);
    dest[len] = '\0';

    return &dest[len];
}

char * ws_strcat(char * dest, char * src) {
    int len = strlen(src);

    memcpy(dest, src, len);
    dest[len] = '\0';

    return &dest[len];
}

ws_handshake_response_t * 
ws_format_response (ws_handshake_request_t * self) {
    char buffer[512];

    BUFFER_CLEAR(buffer);

    char * p = buffer;
    p = ws_strcat(p, self->sec_websocket_key);
    p = ws_strcat(p, WS_MAGIC_STR);

    unsigned char sha_out[20];

    SHA1_CTX sha;
    SHA1Init(&sha);
    SHA1Update(&sha, buffer, BUFFER_SIZE(p, buffer));
    SHA1Final(sha_out, &sha);

    char * b64_out = b64_encode(sha_out, 20);

    BUFFER_CLEAR(buffer);

    p = buffer;
    p = ws_strcat(p, WS_RESPONSE_101_HEADER);
    p = ws_strcat(p, b64_out);
    p = ws_strcat(p, "\r\n\r\n");

    char * response_data = malloc((BUFFER_SIZE(p, buffer) + 1) * sizeof(char));

    BUFFER_CLEAR(response_data);

    ws_strcat(response_data, buffer);

    ws_handshake_response_t * response = calloc(0, sizeof(ws_handshake_response_t));
    response->request = self;
    response->data = response_data;
    response->sec_websocket_accept = b64_out;

    return response;
}


int 
ws_free(ws_handshake_response_t * response) {
    _WS_FREE(response->sec_websocket_accept);
    _WS_FREE(response->data);

    #ifndef _WS_TEST_MOCK

    if(response->request != NULL) {
        _WS_FREE(response->request->method);
        _WS_FREE(response->request->path);
        _WS_FREE(response->request->http_version);
        _WS_FREE(response->request->host);
        _WS_FREE(response->request->upgrade);
        _WS_FREE(response->request->sec_websocket_key);
        _WS_FREE(response->request->sec_websocket_version);
    }

    #endif
}
