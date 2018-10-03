#! /bin/bash
lcov --directory build --capture --output-file build/coverage.info && \
lcov --remove build/coverage.info '/usr/*' $(pwd)'/tests/*' $(pwd)'/build/*' --output-file build/coverage.info && \
lcov --list build/coverage.info
