#ifndef BOOST_CERTIFY_IMPL_RFC2818_VERIFICATION_IPP
#define BOOST_CERTIFY_IMPL_RFC2818_VERIFICATION_IPP

#include <boost/certify/rfc2818_verification.hpp>

#include <boost/asio/ip/address.hpp>
#include <openssl/x509v3.h>

namespace boost
{

namespace certify
{

inline bool
rfc2818_verification::operator()(bool preverified,
                                 boost::asio::ssl::verify_context& ctx)
{
    if (!preverified && !detail::verify_certificate_chain(ctx, hostname_))
    {
        return false;
    }

    // We're only interested in checking the certificate at the end of the
    // chain.
    int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());
    if (depth > 0)
        return true;

    // Try converting the host name to an address. If it is an address then we
    // need to look for an IP address in the certificate rather than a host
    // name.
    boost::system::error_code ec;
    asio::ip::address address = asio::ip::make_address(hostname_, ec);
    bool is_address = !ec;

    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

    auto constexpr gn_free = [](GENERAL_NAMES* p) { GENERAL_NAMES_free(p); };

    // Go through the alternate names in the certificate looking for matching
    // DNS or IP address entries.
    std::unique_ptr<GENERAL_NAMES, decltype(gn_free)> gens{
      static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0)),
      gn_free};

    for (int i = 0; i < sk_GENERAL_NAME_num(gens.get()); ++i)
    {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens.get(), i);
        if (gen->type == GEN_DNS && !is_address)
        {
            ASN1_IA5STRING* domain = gen->d.dNSName;
            if (domain->type == V_ASN1_IA5STRING && domain->data &&
                domain->length)
            {
                char const* pattern =
                  reinterpret_cast<char const*>(domain->data);
                std::size_t pattern_length = domain->length;
                if (match_pattern(pattern, pattern_length, hostname_.c_str()))
                {
                    return true;
                }
            }
        }
        else if (gen->type == GEN_IPADD && is_address)
        {
            ASN1_OCTET_STRING* ip_address = gen->d.iPAddress;
            if (ip_address->type == V_ASN1_OCTET_STRING && ip_address->data)
            {
                if (address.is_v4() && ip_address->length == 4)
                {
                    asio::ip::address_v4::bytes_type bytes =
                      address.to_v4().to_bytes();
                    if (std::memcmp(bytes.data(), ip_address->data, 4) == 0)
                    {
                        return true;
                    }
                }
                else if (address.is_v6() && ip_address->length == 16)
                {
                    asio::ip::address_v6::bytes_type bytes =
                      address.to_v6().to_bytes();
                    if (std::memcmp(bytes.data(), ip_address->data, 16) == 0)
                    {
                        return true;
                    }
                }
            }
        }
    }
    gens = nullptr;

    // No match in the alternate names, so try the common names. We should only
    // use the "most specific" common name, which is the last one in the list.
    auto* name = X509_get_subject_name(cert);
    int i = -1;
    ASN1_STRING* common_name = nullptr;
    while ((i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0)
    {
        X509_NAME_ENTRY* name_entry = X509_NAME_get_entry(name, i);
        common_name = X509_NAME_ENTRY_get_data(name_entry);
    }
    if (common_name && common_name->data && common_name->length)
    {
        auto const* pattern = reinterpret_cast<char const*>(common_name->data);
        std::size_t pattern_length = common_name->length;
        if (match_pattern(pattern, pattern_length, hostname_.c_str()))
            return true;
    }

    return false;
}

inline bool
rfc2818_verification::match_pattern(char const* pattern,
                                    std::size_t pattern_length,
                                    char const* host)
{
    char const* p = pattern;
    char const* p_end = p + pattern_length;
    char const* h = host;

    while (p != p_end && *h)
    {
        if (*p == '*')
        {
            ++p;
            while (*h && *h != '.')
                if (match_pattern(p, p_end - p, h++))
                    return true;
        }
        else if (tolower(*p) == tolower(*h))
        {
            ++p;
            ++h;
        }
        else
        {
            return false;
        }
    }

    return p == p_end && !*h;
}

} // namespace certify
} // namespace boost

#endif // BOOST_CERTIFY_IMPL_RFC2818_VERIFICATION_IPP
