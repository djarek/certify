#include <boost/test/unit_test.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

struct callback
{
    explicit callback(std::string const& domain_name)
      : ver_{domain_name}
    {
    }

    bool operator()(bool preverified, boost::asio::ssl::verify_context& ctx)
    {
        return ver_(preverified, ctx);
    }

    boost::asio::ssl::rfc2818_verification ver_;
};

BOOST_AUTO_TEST_CASE(test1)
{
    boost::asio::io_context io_ctx;
    boost::asio::ssl::context ssl_ctx{boost::asio::ssl::context::tlsv12_client};

    ssl_ctx.set_verify_mode(
      boost::asio::ssl::context::verify_peer |
      boost::asio::ssl::context::verify_fail_if_no_peer_cert);

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream{io_ctx,
                                                                  ssl_ctx};

    boost::asio::ip::tcp::endpoint ep{
      boost::asio::ip::make_address("127.0.0.1"), 4433};

    stream.next_layer().connect(ep);
    stream.set_verify_callback(callback{"example.org"});
    stream.handshake(boost::asio::ssl::stream_base::handshake_type::client);
    stream.shutdown();
    stream.next_layer().close();
}
