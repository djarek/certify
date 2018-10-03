#! /bin/sh
BOOST_URL=https://dl.bintray.com/boostorg/release/1.68.0/source/boost_1_68_0.tar.gz

(curl -L $BOOST_URL --output boost.tar.gz \
&& tar -xf boost.tar.gz \
&& rm boost.tar.gz \
&& cd boost_* \
&& ./bootstrap.sh --prefix=$BOOST_PREFIX --with-toolset=$BOOST_TOOLSET \
&& ./b2 --with-system --with-date_time --with-test install cxxstd=11)
