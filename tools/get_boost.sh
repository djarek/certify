#! /bin/sh

build_dir=$(readlink -f $2)

branch="master"
if [ $1 == "master" ]; then
    branch="develop"
fi

git clone -b $branch --depth 1 https://github.com/boostorg/boost.git boost-root

cd boost-root
git submodule update --init libs/array
git submodule update --init libs/asio
git submodule update --init libs/assert
git submodule update --init libs/beast
git submodule update --init libs/bind
git submodule update --init libs/chrono
git submodule update --init libs/concept_check
git submodule update --init libs/config
git submodule update --init libs/container
git submodule update --init libs/container_hash
git submodule update --init libs/core
git submodule update --init libs/date_time
git submodule update --init libs/detail
git submodule update --init libs/filesystem
git submodule update --init libs/integer
git submodule update --init libs/intrusive
git submodule update --init libs/io
git submodule update --init libs/iterator
git submodule update --init libs/lexical_cast
git submodule update --init libs/math
git submodule update --init libs/move
git submodule update --init libs/mpl
git submodule update --init libs/numeric
git submodule update --init libs/optional
git submodule update --init libs/predef
git submodule update --init libs/preprocessor
git submodule update --init libs/range
git submodule update --init libs/smart_ptr
git submodule update --init libs/static_assert
git submodule update --init libs/system
git submodule update --init libs/throw_exception
git submodule update --init libs/tokenizer
git submodule update --init libs/type_traits
git submodule update --init libs/utility
git submodule update --init libs/winapi
git submodule update --init tools/build
echo Submodule update complete

rm -rf libs/certify
mkdir libs/certify
cp -r $build_dir libs/
