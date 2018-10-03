#ifndef BOOST_CERTIFY_RFC_2818_VERIFICATION_HPP
#define BOOST_CERTIFY_RFC_2818_VERIFICATION_HPP

#include <boost/certify/detail/config.hpp>

#include <boost/asio/ssl/rfc2818_verification.hpp>
#include <boost/asio/ssl/verify_context.hpp>

namespace boost
{
namespace certify
{
namespace detail
{

bool
verify_certificate_chain(boost::asio::ssl::verify_context& ctx,
                         std::string const& hostname);

} // namespace tls
} // namespace detail
} // namespace netu

#if BOOST_CERTIFY_USE_NATIVE_CERTIFICATE_STORE
#if BOOST_WINDOWS
#include <boost/certify/detail/keystore_windows.hpp>
#else
#include <boost/certify/detail/keystore_default.hpp>
#endif
#endif // BOOST_CERTIFY_USE_NATIVE_CERTIFICATE_STORE

namespace boost
{
namespace certify
{

struct rfc2818_verification
{
    explicit rfc2818_verification(std::string hostname)
      : verify_{hostname}
      , hostname_{std::move(hostname)}
    {
    }

    bool operator()(bool preverified, boost::asio::ssl::verify_context& ctx)
    {
        if (!preverified && !detail::verify_certificate_chain(ctx, hostname_))
        {
            return false;
        }

        return verify_(true, ctx);
    }

    boost::asio::ssl::rfc2818_verification verify_;
    std::string hostname_;
};

} // namespace certify
} // namespace boost
#endif // BOOST_CERTIFY_RFC_2818_VERIFICATION_HPP
