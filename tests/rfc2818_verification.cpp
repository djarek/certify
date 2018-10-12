#include <boost/certify/rfc2818_verification.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

namespace boost
{
namespace certify
{

namespace
{

template<typename T>
void
assign_ssl_error(T&&, system::error_code& ec)
{
    ec = {static_cast<int>(::ERR_get_error()),
          boost::asio::error::get_ssl_category()};
}

} // namespace

class certificate_chain
{
public:
    using native_handle_type = STACK_OF(X509) *;

    explicit certificate_chain(native_handle_type h) noexcept
      : handle_{h}
    {
    }

    native_handle_type native_handle() const
    {
        return handle_.get();
    }

    static certificate_chain from_file(
      boost::filesystem::path const& chain_path)
    {
        auto const bio_free = [](::BIO* b) { ::BIO_free(b); };
        std::unique_ptr<::BIO, decltype(bio_free)> file{
          ::BIO_new_file(chain_path.string().c_str(), "rb"), bio_free};
        assert(file != nullptr);
        auto* certs = sk_X509_new_null();
        assert(certs != nullptr);
        while (1)
        {
            auto* cert =
              ::PEM_read_bio_X509(file.get(), nullptr, nullptr, nullptr);
            if (!cert)
            {
                ::ERR_clear_error();
                break;
            }
            auto ret = sk_X509_push(certs, cert);
            assert(ret != 0);
        }
        assert(sk_X509_num(certs) > 0);

        return certificate_chain{certs};
    }

private:
    struct free
    {
        void operator()(native_handle_type h)
        {
            sk_X509_pop_free(h, &::X509_free);
        }
    };

    std::unique_ptr<STACK_OF(X509), free> handle_;
};

class certificate_store
{
public:
    using native_handle_type = ::X509_STORE*;

    explicit certificate_store()
      : handle_{::X509_STORE_new()}
    {
        if (handle_ == nullptr)
        {
            boost::system::error_code ec;
            assign_ssl_error(handle_.get(), ec);
            boost::throw_exception(system::system_error{ec});
        }
    }

    void set_default_paths()
    {
        auto ret = ::X509_STORE_set_default_paths(handle_.get());
        assert(ret == 1);
    }

    native_handle_type native_handle() const
    {
        return handle_.get();
    }

private:
    struct free
    {
        void operator()(native_handle_type h)
        {
            ::X509_STORE_free(h);
        }
    };

    std::unique_ptr<::X509_STORE, free> handle_;
};

std::function<int(bool, boost::asio::ssl::verify_context&)> g_callback;

int
verify_cb(int preverified, X509_STORE_CTX* ctx)
{
    boost::asio::ssl::verify_context verify_ctx{ctx};
    return g_callback(preverified == 1, verify_ctx);
}

class store_ctx
{
public:
    using native_handle_type = ::X509_STORE_CTX*;

    explicit store_ctx(certificate_chain& chain, certificate_store& store)
      : handle_{::X509_STORE_CTX_new()}
    {
        system::error_code ec;
        if (handle_ == nullptr)
        {
            assign_ssl_error(handle_.get(), ec);
            boost::throw_exception(boost::system::system_error{ec});
        }

        assign_ssl_error(
          ::X509_STORE_CTX_init(handle_.get(),
                                store.native_handle(),
                                sk_X509_value(chain.native_handle(), 0),
                                chain.native_handle()),
          ec);

        if (ec)
            boost::throw_exception(boost::system::system_error{ec});
    }

    template<typename T>
    void set_verify_callback(T&& t)
    {
        g_callback = std::forward<T>(t);
        ::X509_STORE_CTX_set_verify_cb(handle_.get(), &verify_cb);
    }

    native_handle_type native_handle() const
    {
        return handle_.get();
    }

    void verify(system::error_code& ec)
    {
        assign_ssl_error(::X509_verify_cert(handle_.get()), ec);
    }

    void verify()
    {
        system::error_code ec;
        verify(ec);
        if (ec)
            boost::throw_exception(boost::system::system_error{ec});
    }

private:
    struct free
    {
        void operator()(native_handle_type h)
        {
            ::X509_STORE_CTX_free(h);
        }
    };

    std::unique_ptr<::X509_STORE_CTX, free> handle_;
};
} // namespace certify
} // namespace boost

void
verify_chain(boost::filesystem::path const& chain_path,
             boost::certify::certificate_store& store)
{
    auto cert_chain = boost::certify::certificate_chain::from_file(chain_path);
    boost::certify::store_ctx ctx{cert_chain, store};

    ctx.set_verify_callback(
      boost::certify::rfc2818_verification{chain_path.stem().string()});
    ctx.verify();
}

int
main()
{
    boost::certify::certificate_store store;
    store.set_default_paths();

    int count = 0;
    for (auto const& entry : boost::filesystem::directory_iterator{
           "libs/certify/tests/res/chains/"})
    {
        if (!boost::filesystem::is_regular_file(entry))
            continue;
        verify_chain(entry.path(), store);
        ++count;
    }
    BOOST_TEST(count > 0);

    return boost::report_errors();
}
