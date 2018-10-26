#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <iostream>

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

void
dump_cert_chain(STACK_OF(X509) * chain, std::string const& file_name)
{
    auto const chain_num = sk_X509_num(chain);
    auto const bio_free = [](::BIO* b) { ::BIO_free(b); };
    std::unique_ptr<::BIO, decltype(bio_free)> file{
      ::BIO_new_file(file_name.c_str(), "wb"), bio_free};
    assert(file != nullptr);
    for (int i = 0; i < chain_num; ++i)
    {
        auto* const cert = sk_X509_value(chain, i);
        assert(cert != nullptr);
        auto const ret = ::PEM_write_bio_X509(file.get(), cert);
        assert(ret == 1);
    }
}

} // namespace

int
main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cerr << "Invalid arguments.\nUsage: download_cert_chain hostname"
                  << std::endl;
        return 1;
    }

    boost::asio::io_context io_ctx;
    boost::asio::ssl::context client_ctx{
      boost::asio::ssl::context::tlsv12_client};

    client_ctx.set_verify_mode(
      boost::asio::ssl::context::verify_peer |
      boost::asio::ssl::context::verify_fail_if_no_peer_cert);
    client_ctx.set_default_verify_paths();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client{io_ctx,
                                                                  client_ctx};
    std::string const domain_name = argv[1];
    boost::asio::connect(client.next_layer(), resolve(io_ctx, domain_name));

    client.set_verify_mode(boost::asio::ssl::verify_peer);
    client.set_verify_callback(
      [domain_name](bool preverified,
                    boost::asio::ssl::verify_context& verify_ctx) {
          auto* const chain =
            ::X509_STORE_CTX_get_chain(verify_ctx.native_handle());
          if (!preverified || sk_X509_num(chain) <= 0)
              return false;
          dump_cert_chain(chain, domain_name + ".crt");

          return true;
      });
    client.handshake(boost::asio::ssl::stream_base::handshake_type::client);
    return 0;
}
