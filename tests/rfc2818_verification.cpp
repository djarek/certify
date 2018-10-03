#include <boost/certify/rfc2818_verification.hpp>


#include <boost/test/unit_test.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

namespace boost
{
namespace certify
{
namespace
{

boost::asio::ip::tcp::resolver::results_type
resolve(boost::asio::io_context& ctx, std::string const& hostname)
{
    boost::asio::ip::tcp::resolver resolver{ctx};
    auto results = resolver.resolve(hostname, "https");
    assert(!results.empty());
    return results;
}

} // namespace

BOOST_AUTO_TEST_CASE(rfc_2818_verification_test)
{
    boost::asio::io_context io_ctx;
    boost::asio::ssl::context client_ctx{
      boost::asio::ssl::context::tlsv12_client};

    client_ctx.set_verify_mode(
      boost::asio::ssl::context::verify_peer |
      boost::asio::ssl::context::verify_fail_if_no_peer_cert);
    client_ctx.set_default_verify_paths();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client{io_ctx,
                                                                  client_ctx};
    std::string const domain_name = "github.com";
    boost::asio::connect(client.next_layer(), resolve(io_ctx, domain_name));

    client.set_verify_mode(boost::asio::ssl::verify_peer);
    client.set_verify_callback(rfc2818_verification{domain_name});
    client.handshake(boost::asio::ssl::stream_base::handshake_type::client);
}

} // namespace certify
} // namespace boost
