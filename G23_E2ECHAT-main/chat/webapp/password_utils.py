import hashlib
import requests

def check_pwned(password:str)->bool:
  # Create a SHA-1 object
  sha1 = hashlib.sha1()

  # Update the object with the input data
  data = password.encode('utf-8')  # Convert the string to bytes
  sha1.update(data)

  # Get the SHA-1 hash value
  hash_value = sha1.hexdigest()
  request="https://api.pwnedpasswords.com/range/"+hash_value[0:5]
  # Send a GET request
  response = requests.get(request)
  # print(response.text)
  if(hash_value[5:].upper() in response.text):
    print("The password had already been pwned")
    return True
  else:
    return False
