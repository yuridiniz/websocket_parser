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
#include "sha1/sha1.h"
#include "b64/b64.h"
#include "strings.h"
#include "ctype.h"

#ifdef _MSC_VER 
//not #if defined(_WIN32) || defined(_WIN64) because we have strncasecmp in mingw
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

#define _WS_STATE_METHOD 0
#define _WS_STATE_PATH 1
#define _WS_STATE_HTTP_VERSION 2
#define _WS_STATE_HOST 3
#define _WS_STATE_UPGRADE 4
#define _WS_STATE_CONNECTION 5
#define _WS_STATE_SEC_KEY 6
#define _WS_STATE_SEC_VERSION 7

static int move_point_to(char ** pointer, char val, int limit);
static char *ws_ltrim(char *s);
static char *ws_rtrim(char *s);
static char *ws_trim(char *s);

#define _WS_FREE(arg) if(arg != NULL) free(arg)
#define WS_MOVE_TOKEN(pointer, token, limit) if(move_point_to(&pointer, token, limit) != 0) return NULL;

static int move_point_to(char ** pointer, char val, int limit) {
    while(*(++*pointer) != val)
    {
        if(*(*pointer) == '\0' || (--limit) == -1)
            return -1;
    }

    return 0;
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


ws_handshake_request_t * 
ws_parser_request(char * data, int data_len) {
    char buffer_key[64];
    char buffer_val[64];
    buffer_key[0] = '\0';
    buffer_val[0] = '\0';

    ws_handshake_request_t * request =  malloc(sizeof(ws_handshake_request_t));

    char * pointer = data;
    char * start_token = pointer;

    int state = _WS_STATE_METHOD;

    int pos = 0;
    while(pos++ < data_len) 
    {
        if(state == _WS_STATE_METHOD || state == _WS_STATE_PATH || state == _WS_STATE_HTTP_VERSION) {
            start_token = pointer;

            pointer = memchr(pointer, ' ', 10);

            int valsize = BUFFER_SIZE(pointer, start_token);

            char * val = malloc((valsize + 1) * sizeof(char));
            ws_strncat(val, start_token, valsize);

            if(state == _WS_STATE_METHOD) {
                request->method = val;
            } else if(state == _WS_STATE_PATH) {
                request->path = val;
            } else if(state == _WS_STATE_HTTP_VERSION) {
                request->http_version = val;
            } else {
                free(val);
            }

            state++;
        } 
        else if(state > _WS_STATE_HTTP_VERSION)
        {
            if(strncasecmp(pointer, "\r\n" , 2) == 0)
                break;

            BUFFER_CLEAR(buffer_key);
            
            start_token = pointer;
            pointer = memchr(pointer, ':', 40);

            ws_strncat(buffer_key, start_token, BUFFER_SIZE(pointer, start_token));

            start_token = ++pointer;
            pointer = memchr(pointer, '\r', 40);

            int valsize = BUFFER_SIZE(pointer, start_token);
            if(valsize + 1 > 64) {
                //TODO Possível ataque;
                break; 
            }

            ws_strncat(buffer_val, start_token, valsize);

            char * trimmed_val = ws_trim(buffer_val);
            char * trimmed_key = ws_trim(buffer_key);

            int trimmed_val_size = strlen(trimmed_val);

            char * val = malloc((trimmed_val_size + 1) * sizeof(char));
            ws_strncat(val, trimmed_val, trimmed_val_size);

            if(strncasecmp(trimmed_key, "host", 4) == 0) {
                request->host = val;
            }
            else if(strncasecmp(trimmed_key, "upgrade", 7) == 0) {
                request->upgrade = val;
            }
            else if(strncasecmp(trimmed_key, "connection", 10) == 0) {
                request->connection = val;
            }
            else if(strncasecmp(trimmed_key, "sec-websocket-key", 17) == 0) {
                request->sec_websocket_key = val;
            }
            else if(strncasecmp(trimmed_key, "sec-websocket-version", 21) == 0) {
                request->sec_websocket_version = val;
            }
            else {
                free(val);
            }

            pointer = memchr(pointer, '\n', 10);
        }

        ++pointer;
    }

    return request;
}


int 
ws_free_req(ws_handshake_request_t * request) {
    _WS_FREE(request->method);
    _WS_FREE(request->path);
    _WS_FREE(request->http_version);
    _WS_FREE(request->host);
    _WS_FREE(request->upgrade);
    _WS_FREE(request->sec_websocket_key);
    _WS_FREE(request->sec_websocket_version);
    _WS_FREE(request);
}

int 
ws_free_resp(ws_handshake_response_t * response) {
    _WS_FREE(response->sec_websocket_accept);
    _WS_FREE(response->data);
    _WS_FREE(response);
}

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

static char *ws_ltrim(char *s)
{
    while(isspace(*s)) s++;
    return s;
}

static char *ws_rtrim(char *s)
{
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}

static char *ws_trim(char *s)
{
    return ws_rtrim(ws_ltrim(s)); 
}