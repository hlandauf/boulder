# `policy-loader` rule file format

`blacklist` rules are loaded into the policy database via a JSON file.  This
rule file has the following structure, currently the only allowed type is
`blacklist`. `base-rules.json` in this directory contains a number of blacklist
rules for special-use domains but this should be built upon further with
high-value domains.

```
{
  "Blacklist": ["example.com", ...],
}
```
