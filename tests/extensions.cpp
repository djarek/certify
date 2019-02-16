#include <boost/certify/extensions.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/core/lightweight_test.hpp>

int
main()
{
    boost::asio::io_context ioc{1};
    boost::asio::ssl::context context{
      boost::asio::ssl::context_base::method::tls_client};
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream{ioc, context};

    boost::string_view hostname = "example.com";

    BOOST_TEST(boost::certify::sni_hostname(stream).empty());
    boost::certify::sni_hostname(stream, static_cast<std::string>(hostname));
    BOOST_TEST(boost::certify::sni_hostname(stream) == hostname);

    return boost::report_errors();
}
