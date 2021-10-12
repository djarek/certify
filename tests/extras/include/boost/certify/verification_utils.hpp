#ifndef BOOST_CERTIFY_VERIFICATION_UTILS_HPP
#define BOOST_CERTIFY_VERIFICATION_UTILS_HPP

#include <boost/certify/https_verification.hpp>

#include <boost/asio/ssl/error.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/system/error_code.hpp>
#include <boost/utility/string_view.hpp>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace boost
{
namespace certify
{

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
              ::PEM_read_bio_X509_AUX(file.get(), nullptr, nullptr, nullptr);
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
    struct chain_free
    {
        void operator()(native_handle_type h)
        {
            sk_X509_pop_free(h, &::X509_free);
        }
    };

    std::unique_ptr<STACK_OF(X509), chain_free> handle_;
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
            system::error_code ec;
            ec = {static_cast<int>(::ERR_get_error()),
                  boost::asio::error::get_ssl_category()};
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

class store_ctx_category : public system::error_category
{
public:
    const char* name() const BOOST_ASIO_ERROR_CATEGORY_NOEXCEPT
    {
        return "certify.store_ctx";
    }

    std::string message(int value) const
    {
        const char* s = ::X509_verify_cert_error_string(value);
        return s ? s : "certify.store_ctx error";
    }
};

inline system::error_category const&
get_store_ctx_category()
{
    static store_ctx_category const instance;
    return instance;
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
            ec = {static_cast<int>(::ERR_get_error()),
                  boost::asio::error::get_ssl_category()};
            boost::throw_exception(system::system_error{ec});
        }

        X509* const cert = sk_X509_value(chain.native_handle(), 0);
        auto const ret = ::X509_STORE_CTX_init(
          handle_.get(), store.native_handle(), cert, chain.native_handle());
        if (ret != 1)
        {

            ec = {static_cast<int>(::ERR_get_error()),
                  boost::asio::error::get_ssl_category()};
            boost::throw_exception(system::system_error{ec});
        }
        ::X509_STORE_CTX_set_verify_cb(handle_.get(),
                                       &detail::verify_server_certificates);
    }

    store_ctx(store_ctx const&) = delete;
    store_ctx& operator=(store_ctx const&) = delete;

    store_ctx(store_ctx&&) = delete;
    store_ctx& operator=(store_ctx&&) = delete;

    ~store_ctx() = default;

    native_handle_type native_handle() const
    {
        return handle_.get();
    }

    void set_server_hostname(string_view hostname)
    {
        auto* param = ::X509_STORE_CTX_get0_param(handle_.get());
        system::error_code ec;
        detail::set_server_hostname(param, hostname, ec);
        if (ec)
            boost::throw_exception(system::system_error{ec});
    }

    void verify(system::error_code& ec)
    {
        auto ret = ::X509_verify_cert(handle_.get());
        if (ret != 1)
        {
            auto const err = ::X509_STORE_CTX_get_error(handle_.get());
            ec = {err, get_store_ctx_category()};
        }
        else
            ec.assign(0, ec.category());
    }

    void verify()
    {
        system::error_code ec;
        verify(ec);
        if (ec)
            boost::throw_exception(system::system_error{ec});
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

void
verify_chain(boost::filesystem::path const& chain_path,
             boost::certify::certificate_store& store,
             system::error_code& ec)
{
    if (!boost::filesystem::is_regular_file(chain_path))
        return;

    auto cert_chain = boost::certify::certificate_chain::from_file(chain_path);
    boost::certify::store_ctx ctx{cert_chain, store};
    ctx.set_server_hostname(chain_path.stem().string());
    ctx.verify(ec);
}

} // namespace certify
} // namespace boost

#endif // BOOST_CERTIFY_VERIFICATION_UTILS_HPP

