#! /bin/bash
lcov --directory bin.v2/ --capture --output-file bin.v2/coverage.info && \
lcov --remove bin.v2/coverage.info \
    '/usr/*' \
    $(pwd)'/boost/throw_exception.hpp' \
    $(pwd)'/boost/exception/*' \
    $(pwd)'/boost/core/*' \
    $(pwd)'/boost/system/*' \
    $(pwd)'/boost/asio/*' \
    $(pwd)'/libs/certify/tests/*' \
    $(pwd)'/bin.v2/*' --output-file bin.v2/coverage.info && \
lcov --list bin.v2/coverage.info
