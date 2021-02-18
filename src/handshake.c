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

static char *ws_ltrim(char *s);
static char *ws_rtrim(char *s);
static char *ws_trim(char *s);
static int set_val(char **prop, char *val);

ws_handshake_response_t *
ws_format_response(ws_handshake_request_t *self)
{
    char buffer[512];

    BUFFER_CLEAR(buffer);

    char *p = buffer;
    p = ws_strcat(p, self->sec_websocket_key);
    p = ws_strcat(p, WS_MAGIC_STR);

    unsigned char sha_out[20];

    SHA1_CTX sha;
    SHA1Init(&sha);
    SHA1Update(&sha, buffer, BUFFER_SIZE(p, buffer));
    SHA1Final(sha_out, &sha);

    char *b64_out = b64_encode(sha_out, 20);

    BUFFER_CLEAR(buffer);

    p = buffer;
    p = ws_strcat(p, WS_RESPONSE_101_HEADER);
    p = ws_strcat(p, b64_out);
    p = ws_strcat(p, "\r\n\r\n");

    char *response_data = malloc((BUFFER_SIZE(p, buffer) + 1) * sizeof(char));

    BUFFER_CLEAR(response_data);

    ws_strcat(response_data, buffer);

    ws_handshake_response_t *response = malloc(sizeof(ws_handshake_response_t));
    response->data = response_data;
    response->sec_websocket_accept = b64_out;

    return response;
}

ws_handshake_request_t *
ws_parser_request(char *data, int data_len)
{
    char buffer_key[64];
    char buffer_val[64];
    buffer_key[0] = '\0';
    buffer_val[0] = '\0';

    ws_handshake_request_t *request = malloc(sizeof(ws_handshake_request_t));
    request->connection = NULL;
    request->method = NULL;
    request->http_version = NULL;
    request->path = NULL;
    request->host = NULL;
    request->sec_websocket_key = NULL;
    request->sec_websocket_version = NULL;
    request->upgrade = NULL;

    char *pointer = data;
    char *start_token = pointer;

    int state = _WS_STATE_METHOD;

    int pos = 0;
    while (pos++ < data_len)
    {
        if (state == _WS_STATE_METHOD || state == _WS_STATE_PATH || state == _WS_STATE_HTTP_VERSION)
        {
            start_token = pointer;

            int end_token = ' ';
            if (state == _WS_STATE_HTTP_VERSION)
                end_token = '\r';

            pointer = memchr(pointer, end_token, 10);
            if (pointer == NULL) {
                ws_free_req(request);
                return NULL;
            }

            int valsize = BUFFER_SIZE(pointer, start_token);

            ws_strncat(buffer_val, start_token, valsize);

            if (state == _WS_STATE_METHOD)
            {
                set_val(&request->method, buffer_val);
            }
            else if (state == _WS_STATE_PATH)
            {
                set_val(&request->path, buffer_val);
            }
            else if (state == _WS_STATE_HTTP_VERSION)
            {
                set_val(&request->http_version, buffer_val);
            }

            state++;
        }
        else if (state > _WS_STATE_HTTP_VERSION)
        {
            if (strncmp(pointer, "\r\n", 2) == 0)
                break;

            start_token = pointer;
            pointer = memchr(pointer, ':', 40);
            if (pointer == NULL)
                return NULL;

            ws_strncat(buffer_key, start_token, BUFFER_SIZE(pointer, start_token));

            start_token = ++pointer;

            pointer = memchr(pointer, '\r', 40);
            if (pointer == NULL)
                return NULL;

            int valsize = BUFFER_SIZE(pointer, start_token);

            ws_strncat(buffer_val, start_token, valsize);

            char *trimmed_key = ws_trim(buffer_key);

            for (int i = 0; trimmed_key[i]; i++)
            {
                trimmed_key[i] = tolower(trimmed_key[i]);
            }

            if (strncmp(trimmed_key, "host", 4) == 0)
            {
                set_val(&request->host, buffer_val);
            }
            else if (strncmp(trimmed_key, "upgrade", 7) == 0)
            {
                set_val(&request->upgrade, buffer_val);
            }
            else if (strncmp(trimmed_key, "connection", 10) == 0)
            {
                set_val(&request->connection, buffer_val);
            }
            else if (strncmp(trimmed_key, "sec-websocket-key", 17) == 0)
            {
                set_val(&request->sec_websocket_key, buffer_val);
            }
            else if (strncmp(trimmed_key, "sec-websocket-version", 21) == 0)
            {
                set_val(&request->sec_websocket_version, buffer_val);
            }

            pointer = memchr(pointer, '\n', 10);
            if (pointer == NULL) {
                ws_free_req(request);
                return NULL;
            }
        }

        ++pointer;
    }

    return request;
}

static int set_val(char** prop, char *val)
{
    char * trimmed_val = ws_trim(val);

    int trimmed_val_size = strlen(trimmed_val);

    *prop = malloc((trimmed_val_size + 1) * sizeof(char));
    if(*prop == NULL)
        return -1;

    ws_strncat(*prop, trimmed_val, trimmed_val_size);
    return 0;
}

void ws_free_req(ws_handshake_request_t *request)
{
    if(request == NULL)
        return;

    free(request->method);
    free(request->path);
    free(request->http_version);
    free(request->host);
    free(request->upgrade);
    free(request->connection);
    free(request->sec_websocket_key);
    free(request->sec_websocket_version);
    free(request);
}

void ws_free_resp(ws_handshake_response_t *response)
{
    if(response == NULL)
        return;

    free(response->sec_websocket_accept);
    free(response->data);
    free(response);
}

char *ws_strncat(char *dest, char *src, int len)
{
    memcpy(dest, src, len);
    dest[len] = '\0';

    return &dest[len];
}

char *ws_strcat(char *dest, char *src)
{
    int len = strlen(src);

    memcpy(dest, src, len);
    dest[len] = '\0';

    return &dest[len];
}

static char *ws_ltrim(char *s)
{
    while (isspace(*s))
        s++;
    return s;
}

static char *ws_rtrim(char *s)
{
    char *back = s + strlen(s);
    while (isspace(*--back))
        ;
    *(back + 1) = '\0';
    return s;
}

static char *ws_trim(char *s)
{
    return ws_rtrim(ws_ltrim(s));
}
