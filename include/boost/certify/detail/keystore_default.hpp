#ifndef BOOST_CERTIFY_DETAIL_KEYSTORE_DEFAULT
#define BOOST_CERTIFY_DETAIL_KEYSTORE_DEFAULT

#include <boost/asio/ssl/rfc2818_verification.hpp>
#include <boost/asio/ssl/verify_context.hpp>

namespace boost
{
namespace certify
{
namespace detail
{

inline bool
verify_certificate_chain(boost::asio::ssl::verify_context& ctx,
                         std::string const& hostname)
{
    return false;
}

} // namespace detail
} // namespace certify
} // namespace boost

#endif // BOOST_CERTIFY_DETAIL_KEYSTORE_DEFAULT