curl -X POST "http://localhost:80/ekyc/1.0.0/submit-kyc" \
-H "Content-Type: application/json" \
-d '{
    "provider-name": "coopnet-kyc-provider",
    "phone-number": "+639209153085",
    "email": "alvillarica@gmail.com",
    "PIN": "1234",
    "personal-info-details": {
        "FirstName": "rodolfo alberto",
        "MiddleName": "asuncion",
        "LastName": "villarica",
        "Birthdate": "1970-feb-02",
        "Gender": "M",
        "Citizenship": "ph",
        "Residency": "us"
    }
}'
