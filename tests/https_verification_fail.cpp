#include <boost/certify/https_verification.hpp>

#include <boost/certify/verification_utils.hpp>
#include <boost/core/lightweight_test.hpp>

int
main()
{
    ::SSL_library_init();

    boost::certify::certificate_store store;
    store.set_default_paths();

    int count = 0;
    for (auto const& entry : boost::filesystem::directory_iterator{
           "libs/certify/tests/res/fail_chains/"})
    {
        boost::system::error_code ec;
        boost::certify::verify_chain(entry.path(), store, ec);
        if (!ec)
            BOOST_ERROR((entry.path().string() + ": expected failure").c_str());
        ++count;
    }
    BOOST_TEST(count > 0);

    return boost::report_errors();
}
