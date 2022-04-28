# bot.py
import base64
import os
import discord
from dotenv import load_dotenv
from cryptoclass import Encryption_Class
import subprocess
import threading


# initialization
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
CHANNEL_ID = os.getenv('CHANNEL_ID')
intents = discord.Intents.default()
intents.members= True
client = discord.Client(intents=intents)
ec = Encryption_Class()


def stdout_piping(process):
    while True:
        realtime_output = process.stdout.readline()

        if realtime_output == '' and process.poll() is not None:
            break

        if realtime_output:
            print("sent: " + realtime_output.strip(), flush=True)


# event loop
@client.event
async def on_ready():
    channel = client.get_channel(int(CHANNEL_ID))

    # when the bot starts, he will check if the RSA public key of the partner was sent in the last message in the channel.
    # (messages starting with "hs-" contain the RSA public key encrypted with static AES key)
    # if it has been sent, this bot will update the partner's RSA public key and reply by sending his own RSA public key encrypted with static AES key 
    # alongside his runtime AES key encrypted with both the partner's RSA public key and the static AES key
    # if it hasn't be sent, this bot will initiate the handshake by sending his own RSA public key encrypted with static AES key
    last_message_channel = (await channel.history(limit=1).flatten())[0]
    if last_message_channel.author != client.user and last_message_channel.content[:3] == "hs-": 
        partner_public_key = ec.aes_decrypt_string(last_message_channel.content[3:], ec.static_aes_key)
        ec.update_partner_public_key(partner_public_key)
        print("updated partner pubkey")
        
        
        # encryption_1 : our runtime AES key will first be encrypted with the partner's RSA public key
        # encryption_2: the result of encryption_1 will be then encrypted by the static AES key
        runtime_aes_encryption_1 = ec.rsa_encrypt_string(ec.own_runtime_aes_key, ec.return_partner_public_key())
        runtime_aes_encryption_2 = ec.aes_encrypt_string(runtime_aes_encryption_1, ec.static_aes_key)

        # our RSA public key will be encrypted with the static AES key
        own_pubkey_encryption = ec.aes_encrypt_string(ec.own_rsa_key_pair[0], ec.static_aes_key)

        # send both keys
        await channel.send(f"hs-{own_pubkey_encryption}")
        await channel.send(f"hs2-{runtime_aes_encryption_2}")
        ec.sent_runtime_aes_key = True
        print("sent runtime AES key encrypted with both partner's RSA public key and static AES key, and own public key encrypted with static AES key")

    # initiate handshake by sending own RSA public key encrypted with static AES key
    else :

        # our RSA public key will be encrypted with the static AES key
        own_pubkey_encryption = ec.aes_encrypt_string(ec.own_rsa_key_pair[0], ec.static_aes_key)

        # send the key
        await channel.send(f"hs-{own_pubkey_encryption}")
        print("initiated handshake by sending own RSA public key encrypted with static AES key")
    

@client.event
async def on_message(message):
    channel = client.get_channel(int(CHANNEL_ID))
    
    # the message starts with "hs-" whenever it contains an RSA public key encrypyed with static AES key
    # so we will update the partner's RSA public key after this message is recieved.
    if message.author != client.user and message.content[:3] == "hs-":

        # decrypt the recieved partner's RSA public key with the static AES key and update partner's RSA public key
        partner_public_key = ec.aes_decrypt_string(message.content[3:], ec.static_aes_key)
        ec.update_partner_public_key(partner_public_key)
        print("updated partner pubkey")
    
    # the message starts with "hs2-" whenever it contains the runtime AES key encrypted with both the partner's RSA public key
    # and the static AES key.
    # we will update the partner's runtime AES key after this message is recieved.
    elif message.author != client.user and message.content[:4] == "hs2-" and not ec.return_partner_runtime_aes_key():

        # decryption_1: the recieved message will first be decrypted using the static AES key.
        # decryption_2: the result of decryption_1 will then be decrypted using our RSA private key.
        # then update partner's runtime AES key
        runtime_aes_decryption_1 = ec.aes_decrypt_string(message.content[4:], ec.static_aes_key)
        runtime_aes_decryption_2 = ec.rsa_decrypt_string(runtime_aes_decryption_1, ec.own_rsa_key_pair[1])
        ec.update_partner_runtime_aes_key(runtime_aes_decryption_2)
        print("updated partner runtime aes key")
        
        # after updating the partner's runtime AES key
        # if we haven't sent our runtime AES key yet, we will send it and we will derive the master runtime AES key using
        # the partner's runtime AES key that we just recieved and our runtime AES key.
        # if we have already sent it, we will just derive the master runtime AES key.
        if not ec.sent_runtime_aes_key:


            # encryption_1 : our runtime AES key will first be encrypted with the partner's RSA public key
            # encryption_2: the result of encryption_1 will be then encrypted by the static AES key
            runtime_aes_encryption_1 = ec.rsa_encrypt_string(ec.own_runtime_aes_key, ec.return_partner_public_key())
            runtime_aes_encryption_2 = ec.aes_encrypt_string(runtime_aes_encryption_1, ec.static_aes_key)
            await channel.send(f"hs2-{runtime_aes_encryption_2}")
            ec.sent_runtime_aes_key = True

            # derive the master runtime AES key (the salt is static, found in .env) and update master runtime AES key
            master_runtime_aes_key = ec.derive_master_runtime_aes_key(f"{ec.own_runtime_aes_key}{ec.return_partner_runtime_aes_key()}", ec.static_hkdf_salt)
            ec.update_master_runtime_aes_key(master_runtime_aes_key)
            print("derived master AES key and sent own runtime AES key to partner")
            print("HANDSHAKE COMPLETED SUCCESSFULLY. SENT AND RECIEVED MESSAGES WILL APPEAR HERE\n------chat history------\n")

            # after the handshake is completed, open a new console to allow users to send messages.
            process = subprocess.Popen([r"..\virtualenv\Scripts\python.exe", "bot_input.py", ec.return_master_runtime_aes_key(), ec.return_partner_public_key()], creationflags=subprocess.CREATE_NEW_CONSOLE, stdout=subprocess.PIPE, encoding='utf-8')

            # read from the opened console stdout in a different thread to avoid blocking
            threading.Thread(target=stdout_piping, args=(process, )).start()

        # just derive the master runtime AES key.
        else: 

            # derive the master runtime AES key (the salt is static, found in .env) and update master runtime AES key
            master_runtime_aes_key = ec.derive_master_runtime_aes_key(f"{ec.return_partner_runtime_aes_key()}{ec.own_runtime_aes_key}", ec.static_hkdf_salt)
            ec.update_master_runtime_aes_key(master_runtime_aes_key)
            print("derived final aes key")
            print("HANDSHAKE COMPLETED SUCCESSFULLY. SENT AND RECIEVED MESSAGES WILL APPEAR HERE\n------chat history------\n")

            # after the handshake is completed, open a new console to allow users to send messages.
            process = subprocess.Popen([r"..\virtualenv\Scripts\python.exe", "bot_input.py", ec.return_master_runtime_aes_key(), ec.return_partner_public_key()], creationflags=subprocess.CREATE_NEW_CONSOLE, stdout=subprocess.PIPE, encoding='utf-8')

            # read from the opened console stdout in a different thread to avoid blocking
            threading.Thread(target=stdout_piping, args=(process, )).start()
        
    else:

        # if the message doesn't start with "hs-" or "hs2-" and it wasn't sent by our bot, then it a text message the partner sent
        if  message.author != client.user and message.content[:3] != "hs-" and message.content[:4] != "hs2-":

            # the text message will be double encrypted with both the master runtime AES key and partner's RSA public key
            # decryption_1: the text message will first be decrypted with the master runtime AES key
            # decryption_2: the result of decryption_1 will be then decrypted with our RSA private key.
            text_message_decryption_1 = ec.aes_decrypt_string(message.content, ec.return_master_runtime_aes_key())
            text_message_decryption_2 = ec.rsa_decrypt_string(text_message_decryption_1, ec.own_rsa_key_pair[1])
            print("received: " + base64.b64decode(text_message_decryption_2.encode("utf-8")).decode("utf-8"))

            # derive a new master runtime AES key after the message is recieved
            ec.update_master_runtime_aes_key(ec.derive_new_master_runtime_aes_key(ec.return_master_runtime_aes_key(), ec.static_hkdf_salt_2))



client.run(TOKEN)
