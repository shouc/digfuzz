cd $1
echo $1
git diff > $2.diff
mv $2.diff ..
cd ..
