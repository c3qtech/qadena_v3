"""
chatpt prompt

given the following json format, write python app to add any number of sample records (using python faker), and provider-name can be either "coopnet-kyc-provider" or "maya-kyc-provider", phone numbers use "+" + MSISDNs, but include the records shown below:  
{
"provider-name": "coopnet-kyc-provider",
"kya-records": [
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
        }
]
}

"""


import sys
import json
from faker import Faker

# Load the existing JSON data
existing_data = {
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
        }
    ]
}

import sys

if len(sys.argv) != 3:
    print("Usage: python generate_random_kyc.py <number of records> <true/false whether to use default data>")
    sys.exit(1)

try:
    number = int(sys.argv[1])
except ValueError:
    print("Error: The first argument must be a valid integer.")
    sys.exit(1)

boolean_arg = sys.argv[2].lower() == 'true'

print("Number of records:", number)
print("Include default records:", boolean_arg)

# Create a Faker instance
fake = Faker()

# Generate new sample records
num_records = number  # Change this to the desired number of records


# if boolean_arg is false, then use an empty list

if boolean_arg:
    total_records = str(num_records + 2)
else:
    total_records = str(num_records)
    # remove the default records
    existing_data["kyc-records"] = []

for _ in range(num_records):
    pin = fake.random_int(min=1000, max=9999)
    # convert to string
    pin = str(pin)
    record = {
        "phone-number": "+" + fake.msisdn(),
        "email": fake.email(),
        "PIN": pin,
        "personal-info-details": {
            "FirstName": fake.first_name(),
            "MiddleName": fake.first_name(),
            "LastName": fake.last_name(),
            "Birthdate": fake.date_of_birth(minimum_age=18, maximum_age=80).strftime("%Y-%b-%d"),
            "Gender": fake.random_element(["M", "F"]),
#            "Citizenship": fake.country_code(representation="alpha-2"),
            "Citizenship": fake.random_element(["us", "ca", "gb", "au", "ph"]),
            "Residency": fake.random_element(["us", "ca", "gb", "au", "ph"])
        }
    }
    existing_data["kyc-records"].append(record)

# Convert the updated data back to JSON
updated_json = json.dumps(existing_data, indent=4)

# Print the updated JSON
#print(updated_json)

# Optionally, you can write the updated JSON to a file
with open("ekyc_" + total_records + ".json", "w") as json_file:
     json_file.write(updated_json)
