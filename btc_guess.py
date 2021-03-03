import random
import smtplib
import hashlib
import argparse
import binascii
import base58
import ecdsa
import codecs
from datetime import datetime

import sys
import re
from time import sleep
from urllib.request import urlopen

max_key = 2**256 - 1


def pretty_hex(n):
    return hex(n)[2:].upper().zfill(64)

parser = argparse.ArgumentParser()
parser.add_argument('--min-key', type=str, default="1", help='Lower bound of sampled range in hex')
parser.add_argument('--max-key', type=str, default=pretty_hex(max_key), help='Upper bound of sampled range in hex')

parser.add_argument('--sender-email', type=str, default="btc.guess@yandex.com", help='Email account from which notifications will be sent')
parser.add_argument('--sender-email-password', type=str, default="Rc672r2M1L4W", help='Email account password')

parser.add_argument('--email-recipient', type=str, default=None, help='Email address to which notifications will be sent')

parser.add_argument('--n', type=int, default=0, help='number of tried private keys, setting n=0 will try keys forever')

parser.add_argument('--send-test-mail', action='store_true', default=False)

# generate n private keys sampled uniformly from [low, high]
def generate(n=1, low=0, high=max_key):
    keys = []
    for i in range(n):
        keys.append(random.randint(low, high))

    return keys

    
def convert_pvk_Hex_to_WIF_Uncompressed(z):
    # Step 1: get the privatekey in extended format, this is hexadecimal upper or lower case.
    private_key_static = z
    # Step 2: adding 80 in the front for select de MAINNET channel bitcoin address
    extended_key = "80"+private_key_static
    # Step 3: first process SHA-256
    first_sha256 = hashlib.sha256(binascii.unhexlify(extended_key)).hexdigest()
    # Step 4: second process SHA-256
    second_sha256 = hashlib.sha256(binascii.unhexlify(first_sha256)).hexdigest()
    # Step 5-6: add checksum info to end of extended key
    final_key = extended_key+second_sha256[:8]
    # Step 7: finally the Wallet Import Format (WIF) is generated in the format base 58 encode of final_key
    WIF = base58.b58encode(binascii.unhexlify(final_key))
    # Step 8: show the private key on usual format WIF for wallet import. Enjoy!
    return WIF.decode()


def convert_pvk_Hex_to_WIF_Compressed(z):
    # Step 1: get the privatekey in extended format, this is hexadecimal upper or lower case.
    private_key_static = z
    # Step 2: adding 80 in the front for select de MAINNET channel bitcoin address
    extended_key = "80"+private_key_static+'01'
    # Step 3: first process SHA-256
    first_sha256 = hashlib.sha256(binascii.unhexlify(extended_key)).hexdigest()
    # Step 4: second process SHA-256
    second_sha256 = hashlib.sha256(binascii.unhexlify(first_sha256)).hexdigest()
    # Step 5-6: add checksum info to end of extended key
    final_key = extended_key+second_sha256[:8]
    # Step 7: finally the Wallet Import Format (WIF) is generated in the format base 58 encode of final_key
    WIFc = base58.b58encode(binascii.unhexlify(final_key))
    # Step 8: show the private key on usual format WIF for wallet import. Enjoy!
    return WIFc.decode()


#Step 1 - get the public_key of private_key, the result is string hex, 512 bits pubkey
def conv_pvkhex_to_bitcoinaddress_uncompressed(z):
    # zk = ecdsa.SigningKey.from_string(z.decode('hex'), curve=ecdsa.SECP256k1)
    zk = ecdsa.SigningKey.from_string(binascii.unhexlify(z), curve=ecdsa.SECP256k1)
    zk_verify = zk.verifying_key

    #result
    z_public_key = b'\x04' + zk.verifying_key.to_string()

    #Step 2 - Making SHA-256 of pub_key and using this first_sha256 for make RIPEMD-160
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(z_public_key).digest())
    ripemd160_result = ripemd160.hexdigest()

    #Step 3 - Adding network bytes on start of result of Step 2
    step3 =  '00' + ripemd160_result
    
    #Step 4 - Making SHA-256 of RIPEMD-160 with network bytes included
    second_sha256 = hashlib.sha256(binascii.unhexlify(step3)).hexdigest()

    #Step 5 - Making SHA-256 of second_sha256
    third_sha256 = hashlib.sha256(binascii.unhexlify(second_sha256)).hexdigest()

    #Step 6 - Get the first 4 bytes of third_sha256
    step6 = third_sha256[:8]

    #Step 7 - Adding the 4 bytes of Step 6 at the end of Step3 to get the final Hex data needed
    step7 = step3+step6

    #Step8 - Making the Base58 encoding of Step 6 to get Bitcoin Public Address
    bitcoin_uncompressed_address_std = base58.b58encode(binascii.unhexlify(step7))

    return bitcoin_uncompressed_address_std.decode()


def conv_pvkhex_to_bitcoinaddress_compressed(z):
    #Get the ECDSA public key
    key = ecdsa.SigningKey.from_string (binascii.unhexlify(z), curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex').decode()

    if(ord(bytearray.fromhex(key_hex[-2:])) % 2 == 0):
        #The last byte of value for Y is Pair, this require add '02' at first

        public_key_compressed = '02' + key_hex[0:64]

        #Making SHA-256 of pubkey compressed and making RIPEMD-160 of this
        public_key_in_bytes = codecs.decode(public_key_compressed, 'hex')
        sha256_public_key_compressed = hashlib.sha256(public_key_in_bytes)
        sha256_public_key_compressed_digest = sha256_public_key_compressed.digest()

        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_public_key_compressed_digest)
        ripemd160_digest = ripemd160.digest()
        ripemd160_hex = codecs.encode(ripemd160_digest, 'hex')

        #Adding network bytes 0x00
        public_key_compressed_bitcoin_network = b'00' + ripemd160_hex
        public_key_compressed_bitcoin_network_bytes = codecs.decode(public_key_compressed_bitcoin_network, 'hex')

        #Making Checksum for MainNet, this is SHA-256 2x turns and get the firsts 4 bytes
        sha256_one = hashlib.sha256(public_key_compressed_bitcoin_network_bytes)
        sha256_one_digest = sha256_one.digest()
        sha256_two = hashlib.sha256(sha256_one_digest)
        sha256_two_digest = sha256_two.digest()
        sha256_2_hex = codecs.encode(sha256_two_digest, 'hex')
        checksum = sha256_2_hex[:8]

        bitcoin_compressed_address_hex = (public_key_compressed_bitcoin_network + checksum).decode('utf-8')
        bitcoin_compressed_address = base58.b58encode(binascii.unhexlify(bitcoin_compressed_address_hex))
        return bitcoin_compressed_address.decode()

    else:
        #The last byte of value for Y is Odd, this require add '03' at first

        public_key_compressed = '03' + key_hex[0:64]

        #Making SHA-256 of pubkey compressed and making RIPEMD-160 of this
        public_key_in_bytes = codecs.decode(public_key_compressed, 'hex')
        sha256_public_key_compressed = hashlib.sha256(public_key_in_bytes)
        sha256_public_key_compressed_digest = sha256_public_key_compressed.digest()

        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_public_key_compressed_digest)
        ripemd160_digest = ripemd160.digest()
        ripemd160_hex = codecs.encode(ripemd160_digest, 'hex')

        #Adding network bytes 0x00
        public_key_compressed_bitcoin_network = b'00' + ripemd160_hex
        public_key_compressed_bitcoin_network_bytes = codecs.decode(public_key_compressed_bitcoin_network, 'hex')

        #Making Checksum for MainNet, this is SHA-256 2x turns and get the firsts 4 bytes
        sha256_one = hashlib.sha256(public_key_compressed_bitcoin_network_bytes)
        sha256_one_digest = sha256_one.digest()
        sha256_two = hashlib.sha256(sha256_one_digest)
        sha256_two_digest = sha256_two.digest()
        sha256_2_hex = codecs.encode(sha256_two_digest, 'hex')
        checksum = sha256_2_hex[:8]

        bitcoin_compressed_address_hex = (public_key_compressed_bitcoin_network + checksum).decode('utf-8')
        bitcoin_compressed_address = base58.b58encode(binascii.unhexlify(bitcoin_compressed_address_hex))
        return bitcoin_compressed_address.decode()
 
def check_balance(address):
    #Add time different of 0 if you need more security on the checks
    WARN_WAIT_TIME = 0

    blockchain_tags_json = [ 
        'total_received',
        'final_balance',
        ]

    SATOSHIS_PER_BTC = 1e+8

    check_address = address

    parse_address_structure = re.match(r' *([a-zA-Z1-9]{1,34})', check_address)
    if ( parse_address_structure is not None ):
        check_address = parse_address_structure.group(1)
    else:
        print( "\nThis Bitcoin Address is invalid" + check_address )
        exit(1)

    #Read info from Blockchain about the Address
    reading_state=1
    while (reading_state):
        try:
            htmlfile = urlopen(f"https://blockchain.info/address/{check_address}?format=json", timeout = 10)
            htmltext = htmlfile.read().decode('utf-8')
            reading_state  = 0
        except:
            reading_state+=1
            print( "Server error, retrying... " + str(reading_state) )
            sleep(reading_state)

    blockchain_info_array = []
    tag = ''
    try:
        for tag in blockchain_tags_json:
            blockchain_info_array.append (
                float( re.search( r'%s":(\d+),' % tag, htmltext ).group(1) ) )
    except:
        print( "Error '%s'." % tag );
        exit(1)

    for i, btc_tokens in enumerate(blockchain_info_array):
        if (blockchain_tags_json[i] == 'final_balance'): 
            return btc_tokens/SATOSHIS_PER_BTC

class Email(object):
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.server = 'smtp.yandex.com'
        self.port = 587
        session = smtplib.SMTP(self.server, self.port)        
        session.ehlo()
        session.starttls()
        session.ehlo
        session.login(self.email, self.password)
        self.session = session

    def send_message(self, subject, body, send_to):
        headers = [
            "From: " + self.email,
            "Subject: " + subject,
            "To: " + send_to,
            "MIME-Version: 1.0",
           "Content-Type: text/plain"]
        headers = "\r\n".join(headers)
        self.session.sendmail(
            self.email,
            send_to,
            headers + "\r\n\r\n" + body)


def send_email(email_account, password, send_to, content):
    gm = Email(email_account, password)
    gm.send_message('private key with balance discovered', content, send_to)

def get_timestamp():
    # dd/mm/YY H:M:S
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")

if __name__ == "__main__":
    args = parser.parse_args()

    if args.send_test_mail:
        print(f"Sending test email from {args.sender_email} to {args.email_recipient}")
        send_email(args.sender_email, args.sender_email_password, args.email_recipient, "This is only test email, no private key here.")
        sys.exit(0)

    f = open("keys_with_balance.txt", "a")


    try:
        for i in range(args.n if args.n != 0 else 2**256):
            pvk = generate(n=1, low=int(args.min_key, base=16), high=int(args.max_key, base=16))[0]
            pvk_hex = pretty_hex(pvk)


            balance = check_balance(conv_pvkhex_to_bitcoinaddress_compressed(pvk_hex))
            msg = f"{get_timestamp()}\n{pvk_hex}\n{convert_pvk_Hex_to_WIF_Uncompressed(pvk_hex)}\n{convert_pvk_Hex_to_WIF_Compressed(pvk_hex)}\n{conv_pvkhex_to_bitcoinaddress_uncompressed(pvk_hex)}\n{conv_pvkhex_to_bitcoinaddress_compressed(pvk_hex)}\nBalance:{balance}"
            print(msg)


            if balance > 0:
                # if found address with non-zero balance, save the keys to file
                f.write(msg)
                f.write("\n\n")
                f.flush()

                # if email address has been specified, recipient will get a notification
                if args.email_recipient is not None:
                    send_email(args.sender_email, args.sender_email_password, args.email_recipient, msg)

            print("\n")

        
    except KeyboardInterrupt:
        print("Exiting...")
        f.close()
