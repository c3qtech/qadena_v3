curl -X POST "http://localhost:80/ekyc/2.0.0/submit-kyc" \
-H "Content-Type: application/json" \
-d '{
    "provider-name": "coopnet-kyc-provider",
    "phone-number": "+639205551212",
    "email": "someguy@gmail.com",
    "PIN": "1234",
    "personal-info-details": {
        "FirstName": "some",
        "MiddleName": "young",
        "LastName": "guy",
        "Birthdate": "1975-jan-22",
        "Gender": "M",
        "Citizenship": "ph",
        "Residency": "us"
    }
}'
