#ifndef BOOST_CERTIFY_IMPL_RFC2818_VERIFICATION_IPP
#define BOOST_CERTIFY_IMPL_RFC2818_VERIFICATION_IPP

#include <boost/certify/https_verification.hpp>

#include <boost/asio/ip/address.hpp>
#include <openssl/x509v3.h>

namespace boost
{
namespace certify
{
namespace detail
{

extern "C" inline int
verify_server_certificates(::X509_STORE_CTX* ctx, void*) noexcept
{
    if (::X509_verify_cert(ctx) == 1)
        return true;

    auto const err = ::X509_STORE_CTX_get_error(ctx);
    if ((err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
         err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) &&
        detail::verify_certificate_chain(ctx))
    {
        ::X509_STORE_CTX_set_error(ctx, X509_V_OK);
        return true;
    }

    return false;
}

void
set_server_hostname(::SSL* handle, string_view hostname, system::error_code& ec)
{
    auto* param = ::SSL_get0_param(handle);
    ::X509_VERIFY_PARAM_set_hostflags(param,
                                      X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    // TODO(djarek): OpenSSL doesn't report an error here?
    if (!X509_VERIFY_PARAM_set1_host(param, hostname.data(), hostname.size()))
        ec = {static_cast<int>(::ERR_get_error()),
              asio::error::get_ssl_category()};
    else
        ec = {};
}

} // namespace detail

inline void
enable_native_https_server_verification(asio::ssl::context& context)
{
    ::SSL_CTX_set_cert_verify_callback(
      context.native_handle(), &detail::verify_server_certificates, nullptr);
}

} // namespace certify
} // namespace boost

#endif // BOOST_CERTIFY_IMPL_RFC2818_VERIFICATION_IPP
