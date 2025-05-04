curl -X POST "http://localhost:80/ekyc/1.0.0/register-kyc-provider" \
-H "Content-Type: application/json" \
-d '{
    "friendly-name": "Maya",
    "name": "maya-kyc-provider",
    "armor-priv-key": "-----BEGIN TENDERMINT PRIVATE KEY-----\nkdf: bcrypt\nsalt: 17CC5AD77CCB1B38DEF803F281B99E08\ntype: eth_secp256k1\n\nHbwolSfDxdtFt/7aIZaTQXiMpKUxIHYtXg+uFKZflaml4PrKIkv86CxcbDfCvM1i\n29NlKdKBqQfnSw6mWe/9ntDYtVIVQ8q6GikWTBc=\n=rruy\n-----END TENDERMINT PRIVATE KEY-----",
    "armor-pass-phrase": "dummy-passphrase",
    "logo": "https://www.mayabank.ph/wp-content/uploads/2022/03/mayabank_logo_mintgreen.svg"
}'

curl -X POST "http://localhost:80/ekyc/1.0.0/register-kyc-provider" \
-H "Content-Type: application/json" \
-d '{
    "friendly-name": "CoopNet",
    "name": "coopnet-kyc-provider",
    "armor-priv-key": "-----BEGIN TENDERMINT PRIVATE KEY-----\nkdf: bcrypt\nsalt: 50E5C5928CEE7D8634FFFBFBDCC81F18\ntype: eth_secp256k1\n\n7q94PFlVN5PjffJIZmTSlHiGhaXkYRszzX3A6DONcQrhjVa4duQoyoLhK5PtHJd4\n+AEm2PGieoNMUOevHIlhT3AzAekw5Nr/aHnDC/I=\n=Esk8\n-----END TENDERMINT PRIVATE KEY-----",
    "armor-pass-phrase": "dummy-passphrase",
    "logo": "https://coopnet.online/img/coopnet-logo.94f920f2.5587f8d8.png"
}'

curl -X POST "http://localhost:80/ekyc/1.0.0/register-kyc-provider" \
-H "Content-Type: application/json" \
-d '{
    "friendly-name": "UnionDigital Bank",
    "name": "unionbank-kyc-provider",
    "armor-priv-key": "-----BEGIN TENDERMINT PRIVATE KEY-----\nkdf: bcrypt\nsalt: 35246C6ECD15296D9301D4FD3E377F53\ntype: eth_secp256k1\n\nCPg+DgsnuK6J7uovyJK2jgxqDyyprxsFoi7OG/LUcNnS9ztLU6Jr1XfgmcH59ua/\nqDLABFWWL6AumtH8aPW1mekWEQeeU6JPwTzrc+0=\n=ZVIF\n-----END TENDERMINT PRIVATE KEY-----",
    "armor-pass-phrase": "dummy-passphrase",
    "logo": "https://digitalpilipinas.ph/wp-content/uploads/2022/07/UD-Logo-Black-on-White.jpg"
}'


curl -X POST "http://localhost:80/ekyc/1.0.0/register-kyc-provider" \
-H "Content-Type: application/json" \
-d '{
    "friendly-name": "GCash",
    "name": "gcash-kyc-provider",
    "armor-priv-key": "-----BEGIN TENDERMINT PRIVATE KEY-----\nkdf: bcrypt\nsalt: 42838C9A7C4377E43673119F909EA5F2\ntype: eth_secp256k1\n\nhPpUm6sfHLsiiHVZpocGCqBAhPAdUVnZOj5z3DpCgl8k7C1rc6eQKLJKTtcQ6tmP\nNUSVCmLieF5uJKwgGBOERH7e3WC216jae9T35ZI=\n=AxWo\n-----END TENDERMINT PRIVATE KEY-----",
    "armor-pass-phrase": "dummy-passphrase",
    "logo": "https://1000logos.net/wp-content/uploads/2023/05/GCash-Logo.png"
}'


