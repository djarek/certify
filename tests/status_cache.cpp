#include <boost/certify/detail/status_cache.hpp>
#include <boost/certify/detail/spki_blacklist.hpp>
#include <boost/core/lightweight_test.hpp>
#include <thread>

int
main()
{
    namespace bc = boost::certify;
    namespace sc = std::chrono;

    {
        // Empty cache returns status unknown
        bc::status_cache cache;
        BOOST_TEST(cache.check("AAA") == bc::certificate_status::unknown);
    }

    {
        bc::status_cache cache;
        BOOST_TEST(cache.check("AAA") == bc::certificate_status::unknown);
        cache.mark_valid("AAA", sc::system_clock::now() + sc::seconds{120});
        BOOST_TEST(cache.check("AAA") == bc::certificate_status::valid);
        cache.revoke("AAA");
        BOOST_TEST(cache.check("AAA") == bc::certificate_status::revoked);

        // If we ever see a revocation, mark_valid must not update
        cache.mark_valid("AAA", sc::system_clock::now() + sc::seconds{120});
        BOOST_TEST(cache.check("AAA") == bc::certificate_status::revoked);
    }

    {
        bc::status_cache cache;
        cache.mark_valid("AAA", sc::system_clock::now() + sc::microseconds{10});
        std::this_thread::sleep_for(std::chrono::microseconds{11});
        BOOST_TEST(cache.check("AAA") == bc::certificate_status::unknown);

        // Stale validity check must not update the status
        cache.mark_valid("AAA", sc::system_clock::now() - sc::microseconds{10});
        BOOST_TEST(cache.check("AAA") == bc::certificate_status::unknown);
    }

    {
        // Use blacklist
        bc::status_cache cache;
        std::string str{bc::detail::spki_blacklist[0].begin(), bc::detail::spki_blacklist[0].end()};
        cache.revoke(str);
        BOOST_TEST(cache.check(str) == bc::certificate_status::revoked);
    }

    return boost::report_errors();
}
