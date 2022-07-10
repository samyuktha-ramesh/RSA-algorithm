# RSA-algorithm
RSA algorithm for encryption and decryption written in Haskell

# How to use
To generate keys: `runghc rsa.hs -gen-keys`

To encrypt: `runghc rsa.hs -encrypt pub.key message message.enc`

To decrypt: `runghc rsa.hs -decrypt priv.key message.enc`
