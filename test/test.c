#include "describe/describe.h"
#include "ws_parser.h"

#define REQUEST_HEADER "GET /chat HTTP/1.1 \r\n\
Host: example.com:8000 \r\n\
Upgrade: websocket \r\n\
Connection: Upgrade \r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ== \r\n\
Sec-WebSocket-Version: 13 \r\n\r\n"


#define MALFORMATED_REQUEST_HEADER "GET /chat HTTP/1.1\r\n\
Host: example.com:8000\r\n\
upgrade  :  websocket  \r\n\
  connection: Upgrade \r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ== \r\n\
Sec-WebSocket-Version: 13 \r\n\r\n"


#define INVALID_HEADER_1 "GET /chat HTTP/1.1 \
Host: example.com:8000\r\n\
upgrade  :  websocket  \r\n\
connection: Upgrade \r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ== \r\n\
Sec-WebSocket-Version: 13 \r\n\r\n"

#define INVALID_HEADER_2 "GET /chat HTTP/1.1 \
Host: example.com:8000\r\n\
:websocket  \r\n\
connection: Upgrade \r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ== \r\n\
Sec-WebSocket-Version: 13 \r\n\r\n"


#define INVALID_HEADER_3 "GET /chat  \
::::\r\n\
:websocket  \r\n\
connection: Upgrade \r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ== \r\n\
Sec-WebSocket-Version: 13 \r\n\r\n"

int main(void)
{
    describe("handshake")
    {
        it("should parse request header")
        {
            ws_handshake_request_t * request = ws_parser_request(MALFORMATED_REQUEST_HEADER, strlen(MALFORMATED_REQUEST_HEADER));

            assert_str_equal(request->method, "GET");
            assert_str_equal(request->path, "/chat");
            assert_str_equal(request->http_version, "HTTP/1.1");
            assert_str_equal(request->host, "example.com:8000");
            assert_str_equal(request->upgrade, "websocket");
            assert_str_equal(request->connection, "Upgrade");
            assert_str_equal(request->sec_websocket_key, "dGhlIHNhbXBsZSBub25jZQ==");
            assert_str_equal(request->sec_websocket_version, "13");

            ws_free_req(request);
        };

        it("avoid crash invalid header 1")
        {
            ws_handshake_request_t * request = ws_parser_request(INVALID_HEADER_1, strlen(INVALID_HEADER_1));

            ws_free_req(request);
        };

        it("avoid crash invalid header 2")
        {
            ws_handshake_request_t * request = ws_parser_request(INVALID_HEADER_2, strlen(INVALID_HEADER_2));

            ws_free_req(request);
        };

        it("avoid crash invalid header 3")
        {
            ws_handshake_request_t * request = ws_parser_request(INVALID_HEADER_3, strlen(INVALID_HEADER_3));

            ws_free_req(request);
        };

        it("should generate sec_websocket_accept from sec_websocket_key")
        {
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

            assert_str_equal(response->sec_websocket_accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

            ws_free_resp(response);
        };

        it("complete websocket hendshake")
        {
            ws_handshake_request_t * request = ws_parser_request(REQUEST_HEADER, strlen(REQUEST_HEADER));

            if(request != NULL) {
                ws_handshake_response_t *response = ws_format_response(request);
                assert_str_equal(response->sec_websocket_accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

                ws_free_resp(response);
            }

            ws_free_req(request);
        };
    };

    return assert_failures();
}