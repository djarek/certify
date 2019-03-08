#ifndef BOOST_CERTIFY_TLS_DETAIL_KEYSTORE_WINDOWS
#define BOOST_CERTIFY_TLS_DETAIL_KEYSTORE_WINDOWS

#include <boost/asio/ssl/verify_context.hpp>
#include <boost/make_unique.hpp>

#include <sstream>
#include <wincrypt.h>

namespace boost
{
namespace certify
{
namespace detail
{
struct cert_context_deleter
{
    void operator()(::CERT_CONTEXT const* ctx)
    {
        ::CertFreeCertificateContext(ctx);
    }
};

struct cert_chain_deleter
{
    void operator()(::CERT_CHAIN_CONTEXT const* ctx)
    {
        ::CertFreeCertificateChain(ctx);
    }
};

inline std::unique_ptr<::CERT_CHAIN_CONTEXT const, cert_chain_deleter>
get_cert_chain_context(::CERT_CONTEXT const* cert_ctx, CERT_CHAIN_PARA* params)
{
    ::CERT_CHAIN_CONTEXT const* ctx = nullptr;
    auto const success =
      ::CertGetCertificateChain(nullptr,
                                cert_ctx,
                                nullptr,
                                cert_ctx->hCertStore,
                                params,
                                CERT_CHAIN_REVOCATION_CHECK_CHAIN,
                                nullptr,
                                &ctx);

    std::unique_ptr<::CERT_CHAIN_CONTEXT const, cert_chain_deleter> ret{ctx};
    if (!success)
    {
        return nullptr;
    }

    return ret;
}

inline bool
verify_certificate_chain(::X509_STORE_CTX* ctx)
{
    auto* const chain = ::X509_STORE_CTX_get_chain(ctx);
    if (sk_X509_num(chain) <= 0)
        return false;

    auto* const leaf_cert = sk_X509_value(chain, 0);
    auto cert_len = ::i2d_X509(leaf_cert, nullptr);
    if (cert_len < 0)
        return false;

    auto cert_der = boost::make_unique_noinit<unsigned char[]>(cert_len);
    auto* buf_ptr = cert_der.get();
    cert_len = ::i2d_X509(leaf_cert, &buf_ptr);
    BOOST_ASSERT(cert_len > 0);

    std::unique_ptr<::CERT_CONTEXT const, cert_context_deleter> cert_ctx{
      ::CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_der.get(), cert_len)};

    char oidPkixKpServerAuth[] = szOID_PKIX_KP_SERVER_AUTH;
    char oidServerGatedCrypto[] = szOID_SERVER_GATED_CRYPTO;
    char oidSgcNetscape[] = szOID_SGC_NETSCAPE;
    std::array<char*, 3> chain_usage = {
      oidPkixKpServerAuth,
      oidServerGatedCrypto,
      oidSgcNetscape,
    };

    ::CERT_CHAIN_PARA chain_params = {sizeof(chain_params)};
    chain_params.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chain_params.RequestedUsage.Usage.cUsageIdentifier =
      static_cast<DWORD>(chain_usage.size());
    chain_params.RequestedUsage.Usage.rgpszUsageIdentifier = chain_usage.data();
    auto const cert_chain_context =
      get_cert_chain_context(cert_ctx.get(), &chain_params);
    if (cert_chain_context == nullptr ||
        cert_chain_context->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR)
        return false;

    ::HTTPSPolicyCallbackData policyData = {
      {sizeof(policyData)},
      AUTHTYPE_SERVER,
      0,
      nullptr,
    };
    ::CERT_CHAIN_POLICY_PARA policy_params = {sizeof(policy_params)};
    policy_params.pvExtraPolicyPara = &policyData;
    ::CERT_CHAIN_POLICY_STATUS policy_status = {sizeof(policy_status)};

    return ::CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
                                              cert_chain_context.get(),
                                              &policy_params,
                                              &policy_status) &&
           policy_status.dwError == 0;
}

} // namespace detail
} // namespace certify
} // namespace boost

#endif // BOOST_CERTIFY_TLS_DETAIL_KEYSTORE_WINDOWS
