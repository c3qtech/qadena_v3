curl -X POST "http://localhost:80/ekyc/1.0.0/bulk-submit-kyc" \
-H "Content-Type: application/json" \
-d '{
    "provider-name": "coopnet-kyc-provider",
    "kyc-records": [
        {
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
        },
        {
            "phone-number": "+639088894480",
            "email": "doryvillarica@gmail.com",
            "PIN": "1234",
            "personal-info-details": {
                "FirstName": "rhodora",
                "MiddleName": "roxas",
                "LastName": "villarica",
                "Birthdate": "1970-feb-03",
                "Gender": "F",
                "Citizenship": "ph",
                "Residency": "us"
            }
        },
        {
            "phone-number": "+123456789",
            "email": "sample1@example.com",
            "PIN": "5678",
            "personal-info-details": {
                "FirstName": "John",
                "MiddleName": "Doe",
                "LastName": "Smith",
                "Birthdate": "1995-jan-15",
                "Gender": "M",
                "Citizenship": "us",
                "Residency": "us"
            }
        },
        {
            "phone-number": "+987654321",
            "email": "sample2@example.com",
            "PIN": "7890",
            "personal-info-details": {
                "FirstName": "Jane",
                "MiddleName": "Doe",
                "LastName": "Johnson",
                "Birthdate": "1992-mar-22",
                "Gender": "F",
                "Citizenship": "us",
                "Residency": "us"
            }
        },
        {
            "phone-number": "+614567890",
            "email": "sample3@example.com",
            "PIN": "2345",
            "personal-info-details": {
                "FirstName": "Michael",
                "MiddleName": "James",
                "LastName": "Williams",
                "Birthdate": "1988-jul-10",
                "Gender": "M",
                "Citizenship": "au",
                "Residency": "au"
            }
        },
        {
            "phone-number": "+442012345678",
            "email": "sample4@example.com",
            "PIN": "1234",
            "personal-info-details": {
                "FirstName": "Sophia",
                "MiddleName": "Grace",
                "LastName": "Wilson",
                "Birthdate": "1998-may-05",
                "Gender": "F",
                "Citizenship": "gb",
                "Residency": "gb"
            }
        },
        {
            "phone-number": "+33123456789",
            "email": "sample5@example.com",
            "PIN": "4321",
            "personal-info-details": {
                "FirstName": "Louis",
                "MiddleName": "Henri",
                "LastName": "Martin",
                "Birthdate": "1990-oct-18",
                "Gender": "M",
                "Citizenship": "fr",
                "Residency": "fr"
            }
        },
        {
            "phone-number": "+551234567890",
            "email": "sample6@example.com",
            "PIN": "9876",
            "personal-info-details": {
                "FirstName": "Isabella",
                "MiddleName": "Marie",
                "LastName": "Garcia",
                "Birthdate": "1985-apr-30",
                "Gender": "F",
                "Citizenship": "br",
                "Residency": "br"
             }
        }
    ]
}'
