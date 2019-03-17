#include <boost/certify/crlset_parser.hpp>

#include <boost/core/lightweight_test.hpp>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <numeric>

const std::uint8_t array[46] = {
  0x02, 0x00, 0x7b, 0x7d, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
  0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  0x02, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02};

int
main()
{
    std::vector<boost::certify::crlset> set =
      boost::certify::parse_crlset(boost::asio::buffer(array));
    BOOST_TEST(set.size() == 1);
    std::array<std::uint8_t, 32> spki;
    std::iota(spki.begin(), spki.end(), 1);
    BOOST_TEST(spki == set.at(0).parent_spki_hash);
    BOOST_TEST(set.at(0).serials.size() == 2);
    std::string serial{{0x01, 0x02}};
    BOOST_TEST(set.at(0).serials.at(0) == serial);
    BOOST_TEST(set.at(0).serials.at(1) == serial);

    auto check_error_case = [](std::size_t n, boost::system::error_code ec) {
        try
        {
            std::vector<boost::certify::crlset> set =
              boost::certify::parse_crlset(boost::asio::buffer(&array, n));
        }
        catch (boost::system::system_error const& err)
        {
            BOOST_TEST(err.code() == ec);
            return;
        }
    };

    check_error_case(1, boost::certify::crlset_error::header_length_truncated);
    check_error_case(3, boost::certify::crlset_error::header_truncated);
    check_error_case(42, boost::certify::crlset_error::serial_truncated);

    return boost::report_errors();
}
