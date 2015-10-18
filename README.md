# Aes Crypto

```
using CodeComb.Security.Aes;

...

var aes = new AesCrypto();
var x = aes.Encrypt("abc");
var y = aes.Decrypt(x);
Console.WriteLine("abc" == y ? "Yes" : "No");
```
