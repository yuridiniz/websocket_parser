#include "bench/bench.h"
#include "ws_parser.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "b64/b64.h"
#include "sha1/sha1.h"

#define REQUEST_HEADER "GET /chat HTTP/1.1 \r\n\
Host: example.com:8000 \r\n\
Upgrade: websocket \r\n\
Connection: Upgrade \r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ== \r\n\
Sec-WebSocket-Version: 13 \r\n\r\n"

void do_sha1(int rep)
{

    BENCHMARK(do_sha1, rep)

    unsigned char *str = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    unsigned char sha_out[20];

    SHA1_CTX sha;
    SHA1Init(&sha);
    SHA1Update(&sha, str, strlen(str));
    SHA1Final(sha_out, &sha);

    END_BENCHMARK(do_sha1)
    BENCHMARK_SUMMARY(do_sha1);
}

void do_b64(int rep)
{
    BENCHMARK(b64_alone, rep)

    unsigned char *str = "1234567891234567890123";
    char *enc = b64_encode(str, strlen(str));

    free(enc);

    END_BENCHMARK(b64_alone)
    BENCHMARK_SUMMARY(b64_alone);
}

void do_ws_request_parser(int rep)
{
    BENCHMARK(ws_request_parse, rep)

    ws_handshake_request_t *request = ws_parser_request(REQUEST_HEADER, strlen(REQUEST_HEADER));
    ws_free_req(request);

    END_BENCHMARK(ws_request_parse)
    BENCHMARK_SUMMARY(ws_request_parse);
}
void do_ws_format_response(int rep)
{
    BENCHMARK(ws_formatter, rep)

    ws_handshake_request_t request;
    request.method = "GET";
    request.path = "/chat";
    request.http_version = "HTTP/1.1";
    request.host = "localhost:8888";
    request.upgrade = "websocket";
    request.connection = "Upgrade";
    request.sec_websocket_version = "13";
    request.sec_websocket_key = "dGhlIHNhbXBsZSBub25jZQ==";

    ws_handshake_response_t *response = ws_format_response(&request);

    ws_free_resp(response);

    END_BENCHMARK(ws_formatter)
    BENCHMARK_SUMMARY(ws_formatter);
}

int main()
{
    do_ws_format_response(1);
    do_ws_format_response(10);
    do_ws_format_response(50);

    do_sha1(50);
    do_b64(50);

    do_ws_request_parser(1);
    do_ws_request_parser(10);
    do_ws_request_parser(50);

    return 0;
}