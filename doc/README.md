
# Building the documentation

Building the documentation requires sphinx (extensions: breathe, and alabaster), make and python.

```sh
apt-get install python-sphinx # http://www.sphinx-doc.org/en/stable/install.html
sudo pip install breathe
sudo pip install alabaster
```

You must patch the `breathe` extension to get Doxygen support working. Follow the instructions below (https://github.com/sphinx-doc/sphinx/issues/3709):

> It's bug of breathe.
> The extension builds doctree with wrong way.

> https://github.com/michaeljones/breathe/blob/d3eae7fac4d2ead062070fd149ec8bf839f74ed5/breathe/renderer/sphinxrenderer.py#L1103

> This code rewrites directly the children attribute of the nodelist[0]. > As a result, the structure of doctree has broken (In detail, the child > nodes of nodelist[0] does not refer nodelist[0] as a parent). That causes this problem.
> The docutils clients have to use the methods of docutils.node.Element. It
> In this case, using Element.insert() works well:

```python
        if nodelist:
            # nodelist[0].children = [term, separator] + nodelist[0].children
            nodelist[0].insert(0, term)
            nodelist[0].insert(1, separator)
        else:
            nodelist = [term]
```

> Please report this to breathe project please.
