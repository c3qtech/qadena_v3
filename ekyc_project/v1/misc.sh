curl -X POST "http://localhost:80/ekyc/1.0.0/reuse-kyc" \
-H "Content-Type: application/json" \
-d '{
    "provider-name": "maya-kyc-provider",
    "from-provider-name": "coopnet-kyc-provider",
    "phone-number": "+639209153085",
    "last-name": "villarica"
}'


curl -X POST "http://localhost:80/ekyc/1.0.0/authenticate-user-reuse-kyc" \
-H "Content-Type: application/json" \
-d '{
    "pin": "1234",
    "otp": "248049",
    "session-id": "04f37597b4896c773daa60cdf688bdc890ff9bb5fbc969fc8829a40d45ea8c22619e5c3ba7a4e2ad7144ade5c873af7ec2c90bb2d2008e814c952ec85ac41b5971dfee7b0bcc87654d43b58f441c50b0bbcfbb5e74643be40617d60624a01c7633bd65220fc855f9ee1e859723e8da74d9fd52fdd239f1bc550e5e74a259954f80f65d60b9a9d75d43c87f2baabdb50118e64405351bb5c897a9abb97bd5c7cdfb6c70504be1a22977fffb610fd28a0b6c0c973a0245dc0bb4fcd7e7d27387cc1d7a777e53bf2593a41ca1838c4a49ada133aa9dcec16764631e4b03d7f27659461a2339de097da9f1"
}'


curl -X POST "http://localhost:80/ekyc/1.0.0/notify-user-reuse-kyc" \
-H "Content-Type: application/json" \
-d '{
    "session-id": "456e6328416a4a2b38747678446d793875457643307468707944762f75354a42385341537365416744633551763164375f7075626b2c7b2270726f76696465722d6e616d65223a226d6179612d6b79632d70726f7669646572222c2270686f6e652d6e756d626572223a222b363339323039313533303835222c226c6173742d6e616d65223a2276696c6c6172696361222c2266726f6d2d70726f76696465722d6e616d65223a22636f6f706e65742d6b79632d70726f7669646572227d29"
}'









