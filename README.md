# Aes Crypto

AppVeyor:[![Build status](https://ci.appveyor.com/api/projects/status/94w3h32wynlyojj8/branch/dev?svg=true)](https://ci.appveyor.com/project/Kagamine/aes/branch/dev)

Travis: [![Build status](https://travis-ci.org/CodeComb/Aes.svg)](https://travis-ci.org/CodeComb/Aes)

An AES crypto library for .Net vNext

```
using CodeComb.Security.Aes;

...

var aes = new AesCrypto();
var x = aes.Encrypt("abc");
var y = aes.Decrypt(x);
Console.WriteLine("abc" == y ? "Yes" : "No");
```
