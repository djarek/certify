#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>

#include <boost/certify/rfc2818_verification.hpp>

#include <iostream>

namespace beast = boost::beast;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

tcp::resolver::results_type
resolve(asio::io_context& ctx, std::string const& hostname)
{
    tcp::resolver resolver{ctx};
    return resolver.resolve(hostname, "https");
}

tcp::socket
connect(asio::io_context& ctx, std::string const& hostname)
{
    tcp::socket socket{ctx};
    asio::connect(socket, resolve(ctx, hostname));
    return socket;
}

std::unique_ptr<ssl::stream<tcp::socket>>
connect(asio::io_context& ctx,
        ssl::context& ssl_ctx,
        std::string const& hostname)
{
    auto stream = boost::make_unique<ssl::stream<tcp::socket>>(
      connect(ctx, hostname), ssl_ctx);
    stream->set_verify_callback(boost::certify::rfc2818_verification{hostname});
    ::SSL_set_tlsext_host_name(stream->native_handle(), hostname.c_str());
    stream->handshake(ssl::stream_base::handshake_type::client);
    return stream;
}

http::response<http::string_body>
get(ssl::stream<tcp::socket>& stream,
    boost::string_view hostname,
    boost::string_view uri)
{
    http::request<http::empty_body> request;
    request.method(http::verb::get);
    request.target(uri);
    request.keep_alive(false);
    request.set(http::field::host, hostname);
    http::write(stream, request);

    http::response<http::string_body> response;
    beast::flat_buffer buffer;
    http::read(stream, buffer, response);

    return response;
}

int
main()
{
    asio::io_context ctx;
    ssl::context ssl_ctx{ssl::context::tls_client};
    auto const hostname = std::string{"github.com"};
    ssl_ctx.set_verify_mode(ssl::context::verify_peer |
                            ssl::context::verify_fail_if_no_peer_cert);
    ssl_ctx.set_default_verify_paths();

    auto stream_ptr = connect(ctx, ssl_ctx, hostname);
    auto response = get(*stream_ptr, hostname, "/");
    std::cout << response << '\n';

    boost::system::error_code ec;
    stream_ptr->shutdown(ec);
    stream_ptr->next_layer().close(ec);
}
