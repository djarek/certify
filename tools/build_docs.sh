#! /bin/sh

if [ "$BUILD_DOCS" != "true" ]; then
  return 0
fi

echo "Generting documentation"
./b2 libs/certify/doc

cd libs/certify/
git checkout gh-pages
cp doc/html/certify.html index.html

echo "Pushing documentation"
git config --global user.email "travis@travis-ci.org"
git config --global user.name "Travis CI"
git config --global push.default current
git add index.html
git commit -m"Documentation from $TRAVIS_COMMIT"

git push https://$GH_TOKEN@github.com/djarek/certify.git > /dev/null 2>&1
