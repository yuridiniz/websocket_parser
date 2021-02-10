#include "describe/describe.h"
#include "handshake.h"

int main(void)
{
    describe("handshake")
    {
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

            ws_free(response);
        };
    };

    return assert_failures();
}