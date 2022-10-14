# PFS_Discord
Perfect Forward secrecy messaging using Discord.

# How Does It Work ?
PFS discord follows some standard encryption and key exchange methods. The goal is to agree on a common AES-256 key after every message. That will maintain perfect forward secrecy (It means even if one key gets compromised, it won't break the encryption of all the chat, it will just break the encryption of one message) This section will explain how this chat works and every step it goes through in detail.


## 1- The Static Variables
Static variables are values/keys that should be present in the `.env` file before the script runs. **They should be the same in both users' scripts. There are 
**two** static variables used for this chat :

1. `STATIC_AES_KEY` : This key is used as an *encryption layer* when sending the **runtime AES key** and the **public RSA key**.
2. `STATIC_HKDF_SALT` : This key is used for *deriving* the **first master runtime aes key** .

## 2- The Runtime Keys
Runtime keys are randomly generated everytime the script runs. The script generates multiple runtime keys while it runs. These are the different kinds of runtime keys it generated and their uses :
1. `Runtime AES-256 Key` : This key is used to encrypt the first message in the chat using *symmetric encryption*. It is transmitted privately between the two parties.
2. `RSA Key Pair`: This key pair is used to transmit the **runtime AES key** using *asymmetric encryption*.
3. `Elliptic Curve Keys` : These keys are generated after every message and the **derived key from the Elliptic-Curve-Diffie-Hellman Key Exchange Method becomes the runtime aes key**. This is done to maintain *perfect forward secrecy* in the chat.

## 3- Initial Handshake
The initial handshake's goal is for the two users to exchange their first two runtime AES keys privately using asymmetric encryption. This is achieved by doing the following steps:

1. User A initiates the handshake by sending his randomly generated runtime RSA public key **ecrnypted with the static AES key**.
2.  User B receives the partner's RSA public key **ecrnypted with the static AES key**, decrypts it using the same static AES key and stores it. User B then sends his RSA public key **encrypted with the static AES key** and also sends his *own generated runtime aes key* **encrypted with both the partner's RSA public key and the static AES key**.
3. User A receives both the partner's runtime RSA public key **encrypted with the static AES key** and the partner's *generated runtime aes key* **encrypted with both User A's RSA public key and the static AES key**, decrypts them using the static AES key and User A's private RSA key. Then User A uses `STATIC_HKDF_SALT` and derives a master runtime AES key using his runtime AES key and the recently received partner's runtime AES key and stores it. (This key is used to encrypt the first message in the chat). Then, User A sends his *own generated runtime aes key* **encrypted with both the partner's RSA public key and the static AES key**. This way, User A will have completed the handshake from his side.
4. User B the partner's *generated runtime aes key* **encrypted with both User B's RSA public key and the static AES key**, decrypts them using the static AES key and User B's private RSA key. Then User B uses `STATIC_HKDF_SALT` and derives a master runtime AES key using his runtime AES key and the recently received partner's runtime AES key and stores it. **(This derived key will be the same for User A and User B since they are using the same salt and the same key derivation function.)**. This way, User B also completes the handshake from his side.
5. Now that the **handshake is completed form both sides**. The chat console opens and the first message can be sent. Let's say User A sends the first message. It will be **encrypted with the master runtime AES key**. User B will receive the message, decrypt it with the **same master runtime AES key and display it.**
6. Now that the first message has been sent. The two users **must agree on a new master runtime AES key** in order to *maintain perfect forward secrecy* in the chat. So after User B receives the message and decrypts it. He will **generate a pair of runtime ellpictic curve keys and send his runtime public Elliptic Curve key to the partner**.
7. User A will **receive the partner's runtime public Elliptic Curve key** and *derive a new master runtime AES key* by using his **own private elliptic curve key** and the recently received **partner's elliptic curve key**. Then User A will send his own **runtime public elliptic curve key.**
8. User B will **receive the partner's runtime public Elliptic Curve key** and *derive a new master runtime AES key* by using his **own private elliptic curve key** and the recently received **partner's elliptic curve key.**
9. Now, the two users may send new messages as they **agreed on a new runtime AES key**. This **elliptic curve key exchange will happen after every message sent to maintain perfect forward secrecy** in the chat. Even though it is *not ideal for fast chatting*, this *chat exchanges offers an almost unbreakable security.*

PFS_Discord requires two parties running the same script. Each party/script must have its own discord bot/application token, but the two parties must share the same static salts and keys.



# 1. Installing Dependencies

## 1. Create a virtual enviroment
It is necessary that the virtual enviroment is named *virtualenv*
```
$ python -m venv virtualenv
```

## 2. Activate the virtual enviroment
### Linux 
```
$ source virtualenv/bin/activate
```
### Windows
```
PFS_Discord> virtualenv\Scripts\activate
```

## 3. Install the required depencdencies
```
$ pip install -r requirements.txt
```

# 2. Update the `.env` File
Some variables in `.env` must be set in order for the script to function.
## 1. Creating a New Discord Bot
Create a new bot/application in discord developers portal and add it to your server. Now you may copy the token given to your created bot and place it inside `.env`.
```
DISCORD_TOKEN=the_assigned_token
```
> Note:
>
> Each party **must have his own DISCORD_TOKEN**. In other words, each party should create a bot and add it to the server in which the communication will happen in.
## 2. Check the following Checkboxes
For the script to function correctly, the following checkboxes must be checked. They can be found in the **Bot** section under the created application.
1. :heavy_check_mark: **PRESENCE INTENT**
2. :heavy_check_mark: **SERVER MEMBERS INTENT**
3. :heavy_check_mark: **MESSAGE CONTENT INTENT**
## 3. Copy the Channel ID
After adding the bots to the server, all the encrypted messaging must happen in **1** channel. For that, copy the channel ID of this channel and place it inside `.env`.
```
CHANNEL_ID=the_channel_id
```
## 4. Generate New Secrets
New salts and keys must be generated for extra security before running the script.
### 1. Run `new_secrets.py`
```
python new_secrets.py
```
This will display new randomly generated secrets.
### 2. Place Them In `.env`
```
STATIC_AES_KEY=generated_aes_key
STATIC_HKDF_SALT=generated_salt
STATIC_HKDF_SALT_2=generated_salt_2
```
> Note:
>
> The above secrets **must be the same** in the `.env` file of both parties.
If you completed all of the above steps successfully, you must now be able to run the script and send messages.


# Running the Script
This will run the script and start or complete the handshake.
```
python bot.py  
```


# Chat Console
When the handshake is completed, a new empty console will open. You can type in it and press Enter to send the message. All sent and received messages will be displayed
in the main console of the bot.
