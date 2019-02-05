#ifndef BOOST_CERTIFY_RFC_2818_VERIFICATION_HPP
#define BOOST_CERTIFY_RFC_2818_VERIFICATION_HPP

#include <boost/certify/detail/config.hpp>

#include <boost/asio/ssl/verify_context.hpp>
#include <string>

namespace boost
{
namespace certify
{
namespace detail
{

bool
verify_certificate_chain(boost::asio::ssl::verify_context& ctx,
                         std::string const& hostname);

} // namespace detail
} // namespace certify
} // namespace boost

#if BOOST_CERTIFY_USE_NATIVE_CERTIFICATE_STORE
#if BOOST_WINDOWS
#include <boost/certify/detail/keystore_windows.hpp>
#elif __APPLE__
#include <boost/certify/detail/keystore_apple.hpp>
#else
#include <boost/certify/detail/keystore_default.hpp>
#endif
#endif // BOOST_CERTIFY_USE_NATIVE_CERTIFICATE_STORE

namespace boost
{
namespace certify
{

class rfc2818_verification
{
public:
    explicit rfc2818_verification(std::string hostname)
      : hostname_{std::move(hostname)}
    {
    }

    inline bool operator()(bool preverified,
                           boost::asio::ssl::verify_context& ctx);

private:
    static inline bool match_pattern(const char* pattern,
                                     std::size_t pattern_length,
                                     const char* host);
    std::string hostname_;
};

} // namespace certify
} // namespace boost

#include <boost/certify/impl/rfc2818_verification.ipp>
#endif // BOOST_CERTIFY_RFC_2818_VERIFICATION_HPP
