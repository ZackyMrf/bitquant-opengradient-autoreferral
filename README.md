# BitQuant by OpenGradient Autoreferral
This script automatically creates multiple Solana wallets and registers them on the BitQuant platform using referral codes to generate rewards for a main account.
## Tools and components required
1. BitQuant Account Refresh Token. Register: [https://www.bitquant.io](https://www.bitquant.io/?invite=-nMuDb1p-E1mmg) (Use Solana Wallet)
2. Solana Wallet Address and Private Key
3. VPS or RDP (OPTIONAL), Get free $200 credit [DigitalOcean](https://m.do.co/c/3f132e0f7e13) for 60 days here: [Register](https://m.do.co/c/3f132e0f7e13)
4. Rotating Residental Proxies
   - Free Proxies Rotating Residental: [ProxyScrape](https://proxyscrape.com/?ref=odk1mmj)
   - Paid Proxies Rotating Residental (Recomended): [922proxy](https://www.922proxy.com/register?inviter_code=d03d4fed) or [Proxy-Cheap](https://app.proxy-cheap.com/r/JysUiH)
6. Node.js LTS How to install:
   - [Linux](https://www.digitalocean.com/community/tutorials/how-to-install-node-js-on-ubuntu-22-04)
   - [Windows](https://www.youtube.com/watch?v=La6kH33-AVM&ab_channel=TheCodeCity)
   - [Termux](https://www.youtube.com/watch?v=5NceYSU4uFI&ab_channel=VectorM%3A)
## How to get your BitQuant Account Refresh Token
- First, login into your [BitQuant](https://www.bitquant.io/?invite=-nMuDb1p-E1mmg) Account use Solana Wallet
- Open your Browser console `CTRL + SHIFT  + I` or `F12`
- Go to `Network` tab and refresh
- Search for `https://securetoken.googleapis.com/v1/token?key=AIzaSyBDdwO2O_Ose7LICa-A78qKJUCEE3nAwsM`
- Select one and go to `Payload`, then copy `refresh_token` value
![image](https://github.com/user-attachments/assets/6fe88bc0-62c4-4980-a40e-68418caa5f5d)
## Modules Installation
- Download script [Manually](https://github.com/im-hanzou/bitquant-opengradient-autoreferral/archive/refs/heads/main.zip) or use git:
```bash
git clone https://github.com/im-hanzou/bitquant-opengradient-autoreferral
```
- Open terminal and make sure you already in bot folder:
```bash
cd bitquant-opengradient-autoreferral
```
- Install modules:
```bash
npm install
```
## Run bot
- Replace `.env` file with your own configuration:
```bash
MAIN_ACCOUNT_REFRESH_TOKEN=AMf-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX < Replace with your own BitQuant Account Refresh Token
MAIN_ACCOUNT_ADDRESS=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX < Replace with your own BitQuant Account Solana Address
PROXY=http://user:pass@host:port < Replace with your own Rotating Proxy
```
- Run the script: 
```bash
node index.js
```
# Notes
- You can just run this bot at your own risk, I'm not responsible for any loss or damage caused by this bot.
- This bot is for educational purposes only.
- Another bot: [BitQuant Auto Chat Bot](https://github.com/najibyahya/Open-Gradient-Bot-Chat) by NajibYahya
