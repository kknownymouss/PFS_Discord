import base64
import os
import discord
from dotenv import load_dotenv
from cryptoclass import Encryption_Class
import sys

# INITS
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
CHANNEL_ID = os.getenv('CHANNEL_ID')
intents = discord.Intents.default()
intents.members= True
client = discord.Client(intents=intents)
ec = Encryption_Class()


# update the needed values. They will be passed with the subprocess.Popen function
ec.update_master_runtime_aes_key(sys.argv[1])
ec.update_partner_public_key(sys.argv[2])


# event loop
@client.event
async def on_ready():
    channel = client.get_channel(int(CHANNEL_ID))

    # accept a text message, encode it with base64 and double encrypt it and then send it to the channel.
    while True:
        msg = input("")

        # the printed msg will get piped to the main console.
        print(msg)
        
        b64_msg = base64.b64encode(msg.encode("utf-8")).decode("utf-8")

        # encryption_1: the text message will first be encrypted with the partner's RSA public key.
        # encryption_2: the result of encryption_1 will then be encrypted by the master runtime AES key.
        text_message_encryption_1 = ec.rsa_encrypt_string(b64_msg, ec.return_partner_public_key())
        text_message_encryption_2 = ec.aes_encrypt_string(text_message_encryption_1, ec.return_master_runtime_aes_key())

        # send the double encrypted text message
        await channel.send(text_message_encryption_2)

        # derive a new master runtime AES key after the message is sent
        ec.update_master_runtime_aes_key(ec.derive_new_master_runtime_aes_key(ec.return_master_runtime_aes_key(), ec.static_hkdf_salt_2))


client.run(TOKEN)