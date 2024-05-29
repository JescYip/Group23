import hmac, base64, struct, hashlib, time
import os
def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    #decoding our key
    msg = struct.pack(">Q", intervals_no)
    #conversions between Python values and C structs represente
    h = hmac.new(key, msg, hashlib.sha1)
    print(h)
    h = h.digest()
    o = o = h[19] & 15
    print(f"len of h is {len(h)}")
    print(f"h[19] is {h[19]}")
    print(o)
    #Generate a hash using both of these. Hashing algorithm is HMAC
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    #unpacking
    return h

def get_totp_token(secret):
    #ensuring to give the same otp for 30 seconds
    x = str(get_hotp_token(secret,intervals_no=int(time.time())//30))
    #adding 0 in the beginning till OTP has 6 digits
    while len(x)!=6:
        x = '0' + x
    return x
def valid_totp_token(secret,num:int):
    #ensuring to give the same otp for 30 seconds
    x =str(get_hotp_token(secret,intervals_no=int(time.time())//30-num))
    #adding 0 in the beginning till OTP has 6 digits
    while len(x)!=6:
        x= '0' + x
    return x

def get_valid_TOTP(secret):
    valid_TOTP=[]
    for i in range(3):
        valid_TOTP.append(valid_totp_token(secret,i))
    print(valid_TOTP)
    return valid_TOTP

def get_otp_counter(secret, otp:str)->int:
    current = int(time.time())//30
    valid_otp=get_valid_TOTP(secret)
    i=0
    for o in valid_otp:
        if(o==otp):
            break
        i+=1
    return current-i

def validate_otp(secret:str, otp:str)->bool:
    if(otp in get_valid_TOTP(secret)):
      return True
    return False

def is_replayed(secret, otp: str, counter:int)->bool:
    if(validate_otp(secret, otp)):
      if(get_otp_counter(secret, otp)>counter):
        return False
    return True

def generate_secret():
    random_bytes = os.urandom(16)
    # random_string = ''.join(chr(byte) for byte in random_bytes)
    encoded_data = base64.b32encode(random_bytes).decode("utf-8")
    return encoded_data
# data=generate_secret(8)
# # encoded_data = base64.b32decode(encoded_data)
# print(encoded_data)