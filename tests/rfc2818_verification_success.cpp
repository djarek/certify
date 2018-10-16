#include <boost/certify/rfc2818_verification.hpp>

#include <boost/certify/verification_utils.hpp>
#include <boost/core/lightweight_test.hpp>

int
main()
{
    boost::certify::certificate_store store;
    store.set_default_paths();

    int count = 0;
    for (auto const& entry : boost::filesystem::directory_iterator{
           "libs/certify/tests/res/chains/"})
    {
        boost::certify::verify_chain(entry.path(), store);
        ++count;
    }
    BOOST_TEST(count > 0);

    return boost::report_errors();
}
