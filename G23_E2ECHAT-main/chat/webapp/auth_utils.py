import otp_utils
import password_utils
import bcrypt
import unicodedata
def hash_pwd(password: str) -> str:
    """
    Parameters:
        - password: string of plain password
    
    Return:
        string of salted hash digest
    """
    # TODO: Implement the hashing functionalities
    bytes = password.encode('utf-8')

    salt = bcrypt.gensalt()
    print(bytes)

    hash = bcrypt.hashpw(bytes, salt)
    return hash

def verify_pwd(password: str, hash: str) -> bool:
    """
    Parameters:
        - password: string of plain passwrod
        - hash: a hashed password to compare against
    
    Return:
        True if the password matches the hash, or False otherwise.
    """
    password_bytes=password.encode('utf-8')
    hash_bytes = hash.encode()
    print(password_bytes)
    result=bcrypt.checkpw(password_bytes,hash_bytes)
    return result

def validate_pwd(password: str) -> bool:
    """
    Parameters:
        - password: string of plain password

    Return:
        True if the password satisfy the conditions specified in the requeirements, or False otherwise.
    """

    password = unicodedata.normalize('NFKC', password) # normalized the password to accomodate unicode characters
    if len(password)<8:
        return False
    
    if(password_utils.check_pwned(password)):
      return False
    
    return True


def generate_totp(secret: str) -> str:
    """
    Parameters:
        - secret: shared secret between server and client

    Return:
        6-digit OTP
    """

def generate_otp_secret():
    return otp_utils.generate_secret()
    
def verify_otp(secret, submitted_otp, last_counter):
    isValid = otp_utils.validate_otp(secret, submitted_otp)
    if not isValid:
        return False
    isReplay = otp_utils.is_replayed(secret, submitted_otp, last_counter)
    if isReplay:
        return False
    return True

def verify_new_otp(secret, submitted_otp):
    isValid = otp_utils.validate_otp(secret, submitted_otp)
    return isValid

def get_accepted_otp_counter(secret, submitted_otp):
    return otp_utils.get_otp_counter(secret, submitted_otp)
