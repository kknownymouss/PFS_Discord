# PFS_Discord
Perfect Forward secrecy messaging using Discord.

# How Does It Work ?
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
