# Information about this repository

This repository was created from the original wish-c99 using the
following commands:

```sh
git clone --single-branch -b v0.8.0-release foremost.cto.fi:/git/wish-c99 wish-c99-public --depth=250
echo d4382f5a0999913767ee9a057e1e00593bd8a0af >.git/info/grafts
git filter-branch -- --all
git remote remove origin
#Check that there are not other remotes
git prune
git gc --aggressive
```

## Get list of contributors

```sh
git shortlog -e -s -n
```
