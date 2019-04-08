#! /bin/sh

build_dir=$2

branch="master"
if [ "$1" = "master" ]; then
    branch="develop"
fi

git clone -b $branch --depth 1 https://github.com/boostorg/boost.git boost-root

cd boost-root
git submodule update --init --depth 1 --jobs 4 \
    libs/array \
    libs/asio \
    libs/assert \
    libs/beast \
    tools/boost_install \
    libs/bind \
    libs/chrono \
    libs/concept_check \
    libs/config \
    libs/container \
    libs/container_hash \
    libs/core \
    libs/date_time \
    libs/detail \
    libs/endian \
    libs/filesystem \
    libs/integer \
    libs/intrusive \
    libs/io \
    libs/iterator \
    libs/lexical_cast \
    libs/math \
    libs/move \
    libs/mpl \
    libs/mp11 \
    libs/numeric \
    libs/optional \
    libs/predef \
    libs/preprocessor \
    libs/range \
    libs/smart_ptr \
    libs/static_assert \
    libs/system \
    libs/throw_exception \
    libs/type_traits \
    libs/utility \
    libs/winapi \
    tools/build \

echo Submodule update complete

rm -rf libs/certify
mkdir libs/certify
cp -r $build_dir libs/
