curl -X POST "http://localhost:80/ekyc/2.0.0/authenticate-kyc" \
-H "Content-Type: application/json" \
-d '{
    "from-provider-name": "coopnet-kyc-provider",
    "session-id":"0445587ed60a4b37c584b7c845853531d96301523a0b8bb69756af79d98e362f89b74bd4840958c7571541169d06d950e16532d9a0784137ba4cd1fb006dc0596abeae36ea1fca6b4d0b9059e67cc42ab2443c85c41013fa7798dd0ee3e785d2e84c636651f0dde02dfedb36f04b09f0687f78bedba9330fcb31470a6e9c640c8777a4f922eb89a7ec062d5f731ee2499c6f0742df0016d7ee8870d93189df4c9a07e4fdf6",
    "otp": "111111",
    "pin": "not used",
    "last-name": "villarica"
}'








