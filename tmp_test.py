import requests
from bs4 import BeautifulSoup
import sys

URL = "http://127.0.0.1:5000"

def test_login(email, password, role, expected_redirect):
    print(f"Testing {role} login...")
    session = requests.Session()
    
    # Get login page for CSRF
    res = session.get(f"{URL}/login")
    soup = BeautifulSoup(res.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    if not csrf_input:
        print("ERROR: CSRF token not found on login page!")
        return False
    csrf_token = csrf_input["value"]
    
    # Submit login
    data = {
        "csrf_token": csrf_token,
        "email": email,
        "password": password,
        "role": role
    }
    res = session.post(f"{URL}/login", data=data)
    
    # Should redirect to /verify-otp
    if "/verify-otp" not in res.url:
        print(f"ERROR: Did not reach OTP page. Current URL: {res.url}")
        print("Content:", res.text[:200])
        return False
        
    soup = BeautifulSoup(res.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    if not csrf_input:
        print("ERROR: CSRF token not found on OTP page!")
        return False
    csrf_token = csrf_input["value"]
    
    # Submit OTP 123456
    data = {"csrf_token": csrf_token, "otp": "123456"}
    res = session.post(f"{URL}/verify-otp", data=data)
    
    # Should redirect to dashboard
    if expected_redirect not in res.url:
        print(f"ERROR: Expected {expected_redirect}, got {res.url}")
        print("Content:", res.text[:200])
        return False
        
    print(f"SUCCESS: {role} logged in and reached {res.url}")
    return True

success = True
success &= test_login("24bcp129@sot.pdpu.ac.in", "student_129", "student", "/student")
success &= test_login("24bcp122@sot.pdpu.ac.in", "staff_122", "staff", "/staff")
success &= test_login("24bcp104@sot.pdpu.ac.in", "admin_104", "admin", "/admin")

if not success:
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
