const fs = require('fs');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const readline = require('readline');
const { Keypair } = require('@solana/web3.js');
const bs58 = require('bs58');
const nacl = require('tweetnacl');
const chalk = require('chalk');
require('dotenv').config();

class SolanaAutoRegister {
    constructor() {
        this.results = [];
        this.mainAccountToken = process.env.MAIN_ACCOUNT_TOKEN;
        this.mainAccountAddress = process.env.MAIN_ACCOUNT_ADDRESS;
        this.proxy = process.env.PROXY;
    }

    createAxiosInstance(proxy = null) {
        const config = {
            timeout: 60000,
            headers: {
                'accept': '*/*',
                'accept-language': 'en,en-US;q=0.9,id;q=0.8,zh-CN;q=0.7,zh;q=0.6',
                'origin': 'https://www.bitquant.io',
                'priority': 'u=1, i',
                'referer': 'https://www.bitquant.io/',
                'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'cross-site',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36'
              }
        };

        if (proxy) {
            config.httpsAgent = new HttpsProxyAgent(proxy);
            config.httpAgent = new HttpsProxyAgent(proxy);
        }
        
        return axios.create(config);
    }

    async makeRequest(method, url, data = null, headers = {}, proxy = null) {
        try {
            const axiosInstance = this.createAxiosInstance(proxy);
            const config = {
                method: method,
                url: url,
                headers: { ...axiosInstance.defaults.headers, ...headers }
            };
            
            if (data) {
                config.data = data;
                if (!headers['content-type']) {
                    config.headers['content-type'] = 'application/json';
                }
            }
            
            const response = await axiosInstance(config);
            return response.data;
            
        } catch (error) {
            throw error;
        }
    }

    generateWallet() {
        try {
            const keypair = Keypair.generate();
            const encode = bs58.encode || bs58.default?.encode || bs58;
            const privateKey = typeof encode === 'function' ? encode(keypair.secretKey) : bs58(keypair.secretKey);
            const address = keypair.publicKey.toString();
            
            return {
                privateKey,
                address,
                keypair
            };
        } catch (error) {
            console.error(chalk.red('Error in generateWallet:'), error);
            throw error;
        }
    }

    createSignatureMessage(address) {
        const nonce = Date.now();
        const message = `bitquant.io wants you to sign in with your **blockchain** account:\n${address}\n\nURI: https://bitquant.io\nVersion: 1\nChain ID: solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;
        return message;
    }

    signMessage(message, privateKey) {
        try {
            const decode = bs58.decode || bs58.default?.decode;
            const encode = bs58.encode || bs58.default?.encode || bs58;
            
            const keypair = Keypair.fromSecretKey(decode(privateKey));
            const messageBytes = new TextEncoder().encode(message);
            const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
            const signatureBase58 = typeof encode === 'function' ? encode(signature) : bs58(signature);
            return signatureBase58;
        } catch (error) {
            console.error(chalk.red('Error in signMessage:'), error);
            throw error;
        }
    }

    async generateInviteCode() {
        try {
            const url = 'https://quant-api.opengradient.ai/api/invite/generate';
            const payload = {
                address: this.mainAccountAddress
            };
            const headers = {
                'authorization': `Bearer ${this.mainAccountToken}`,
                'content-type': 'application/json'
            };
            
            const response = await this.makeRequest('POST', url, payload, headers, this.proxy);
            return response.invite_code;
        } catch (error) {
            console.error(chalk.red('[ERROR] Failed to generate invite code:'), error.message);
            throw error;
        }
    }

    async checkWhitelist(address, proxy = null) {
        const url = `https://quant-api.opengradient.ai/api/whitelisted?address=${address}`;
        return await this.makeRequest('GET', url, null, {}, proxy);
    }

    async autoRegister(address, inviteCode, proxy = null) {
        try {
            const url = 'https://quant-api.opengradient.ai/api/invite/use';
            const payload = {
                code: inviteCode,
                address: address
            };
            await this.makeRequest('POST', url, payload, {}, proxy);
            return true;
        } catch (error) {
            console.error(chalk.red(`[ERROR] Registration failed for ${address}:`), error.message);
            return false;
        }
    }

    async authWallet(address, message, signature, proxy = null) {
        const url = 'https://quant-api.opengradient.ai/api/verify/solana';
        const payload = { address, message, signature };
        return await this.makeRequest('POST', url, payload, {}, proxy);
    }

    async accountSign(token, proxy = null) {
        const url = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=AIzaSyBDdwO2O_Ose7LICa-A78qKJUCEE3nAwsM';
        const payload = { token: token, returnSecureToken: true };
        const headers = {
            'x-client-version': 'Chrome/JsCore/11.6.0/FirebaseCore-web',
            'x-firebase-gmpid': '1:976084784386:web:bb57c2b7c2642ce85b1e1b'
        };
        return await this.makeRequest('POST', url, payload, headers, proxy);
    }

    async accountLookup(idToken, proxy = null) {
        const url = 'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=AIzaSyBDdwO2O_Ose7LICa-A78qKJUCEE3nAwsM';
        const payload = { idToken: idToken };
        const headers = {
            'x-client-version': 'Chrome/JsCore/11.6.0/FirebaseCore-web',
            'x-firebase-gmpid': '1:976084784386:web:bb57c2b7c2642ce85b1e1b'
        };
        return await this.makeRequest('POST', url, payload, headers, proxy);
    }

    async getToken(refreshToken, proxy = null) {
        const url = 'https://securetoken.googleapis.com/v1/token?key=AIzaSyBDdwO2O_Ose7LICa-A78qKJUCEE3nAwsM';
        const payload = `grant_type=refresh_token&refresh_token=${refreshToken}`;
        const headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'x-client-version': 'Chrome/JsCore/11.6.0/FirebaseCore-web',
            'x-firebase-gmpid': '1:976084784386:web:bb57c2b7c2642ce85b1e1b'
        };
        return await this.makeRequest('POST', url, payload, headers, proxy);
    }

    async getStatus(address, accessToken, proxy = null) {
        const url = `https://quant-api.opengradient.ai/api/activity/stats?address=${address}`;
        const headers = {
            'authorization': `Bearer ${accessToken}`,
            'content-type': 'application/json'
        };
        return await this.makeRequest('GET', url, null, headers, proxy);
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async processWallet(index) {
        try {
            console.log(chalk.cyan(`[${index}]`), chalk.yellow('🔄 Generating new wallet...'));
            const wallet = this.generateWallet();
            
            console.log(chalk.cyan(`[${index}]`), chalk.blue('📱 Generated address:'), chalk.white(wallet.address));
            
            console.log(chalk.cyan(`[${index}]`), chalk.yellow('🎫 Generating invite code...'));
            const inviteCode = await this.generateInviteCode();
            console.log(chalk.cyan(`[${index}]`), chalk.green('✅ Generated invite code:'), chalk.white(inviteCode));
            
            console.log(chalk.cyan(`[${index}]`), chalk.yellow('📝 Attempting registration...'));
            const registerSuccess = await this.autoRegister(wallet.address, inviteCode, this.proxy);
            
            if (!registerSuccess) {
                console.log(chalk.cyan(`[${index}]`), chalk.red('❌ Registration failed, skipping...'));
                return null;
            }

            console.log(chalk.cyan(`[${index}]`), chalk.green('✅ Registration successful! Authenticating...'));
            
            const message = this.createSignatureMessage(wallet.address);
            const signature = this.signMessage(message, wallet.privateKey);
            const authResult = await this.authWallet(wallet.address, message, signature, this.proxy);

            console.log(chalk.cyan(`[${index}]`), chalk.green('🔐 Authentication successful! Getting tokens...'));
            
            const signResult = await this.accountSign(authResult.token, this.proxy);
            await this.accountLookup(signResult.idToken, this.proxy);
            const tokenResult = await this.getToken(signResult.refreshToken, this.proxy);
            const accessToken = tokenResult.access_token;

            console.log(chalk.cyan(`[${index}]`), chalk.yellow('📊 Getting account stats...'));
            
            const status = await this.getStatus(wallet.address, accessToken, this.proxy);

            const result = {
                privateKey: wallet.privateKey,
                address: wallet.address,
                inviteCode: inviteCode,
                stats: status
            };

            console.log(chalk.cyan(`[${index}]`), chalk.green('🎉 Success!'), 
                       chalk.magenta('Points:'), chalk.white(status.points || 0), 
                chalk.magenta('Messages:'), chalk.white(`${status.message_count || 0}/${status.daily_message_limit || 0}`));
            console.log(chalk.cyan(`[${index}]`), chalk.green('🔗 Success referred to'), chalk.white(this.mainAccountAddress));

            return result;

        } catch (error) {
            console.error(chalk.cyan(`[${index}]`), chalk.red('❌ Error processing wallet:'), error.message);
            return null;
        }
    }

    async saveResult(result, index) {
        if (!result) return;
        let output = ``;

        output += `Success referred to: ${this.mainAccountAddress} \n`;
        output += `Private Key: ${result.privateKey}\n`;
        output += `Address: ${result.address}\n`;
        output += `Invite Code: ${result.inviteCode}\n`;
        output += `Response Stats: ${JSON.stringify(result.stats, null, 2)}\n`;
        output += '\n';

        fs.appendFileSync('wallets.txt', output);
    }

    async getUserInput() {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
    
        return new Promise((resolve) => {
            rl.question(chalk.yellow('How many wallets to register?: '), (walletCount) => {
                rl.close();
                const count = parseInt(walletCount.trim());
                if (isNaN(count) || count <= 0) {
                    console.error(chalk.red('❌ Please enter a valid number greater than 0'));
                    process.exit(1);
                }
                resolve({
                    walletCount: count
                });
            });
        });
    }

    validateEnvironment() {
        if (!this.mainAccountToken) {
            console.error(chalk.red('❌ MAIN_ACCOUNT_TOKEN is required in .env file!'));
            return false;
        }
        if (!this.mainAccountAddress) {
            console.error(chalk.red('❌ MAIN_ACCOUNT_ADDRESS is required in .env file!'));
            return false;
        }
        if (!this.proxy) {
            console.error(chalk.red('❌ PROXY is required in .env file!'));
            return false;
        }
        return true;
    }

    async run() {
        console.log(chalk.cyan.bold(`
    ╔══════════════════════════════════════════════╗
    ║    BitQuant by OpenGradient Autoreferral     ║
    ║    Github: https://github.com/im-hanzou      ║
    ╚══════════════════════════════════════════════╝
    `));
        
        if (!this.validateEnvironment()) {
            return;
        }

        console.log(chalk.green('✅ Environment variables loaded!'));
        console.log(chalk.blue('🔑 Main account token:'), chalk.white(this.mainAccountToken.slice(0, 40) + '...'));
        console.log(chalk.blue('👤 Main account:'), chalk.white(this.mainAccountAddress));
        console.log(chalk.blue('🌐 Using proxy:'), chalk.white(this.proxy));
        console.log('');

        const userInput = await this.getUserInput();
        const walletCount = userInput.walletCount;

        console.log(chalk.cyan(`\n🎯 Starting registration for ${walletCount} wallets...`));

        let successCount = 0;

        for (let i = 1; i <= walletCount; i++) {
            console.log(chalk.magenta(`\n🔥 Processing wallet ${i}/${walletCount}`));
            console.log(chalk.gray('━'.repeat(50)));

            const result = await this.processWallet(i);
            
            if (result) {
                this.results.push(result);
                await this.saveResult(result, i);
                successCount++;
            }
        }

        console.log(chalk.green('\n     🎊 === REGISTRATION COMPLETE ==='));
        console.log(chalk.magenta('📈 SUMMARY:'));
        console.log(chalk.white(`   ✅ Successfully registered: ${successCount}/${walletCount} wallets`));
        console.log(chalk.white(`   💾 Results saved to: wallets.txt`));
        
        if (successCount > 0) {
            console.log(chalk.white(`   🌟 Total ${successCount} wallets succesfully registered!\n`));
        }
    }
}

(async () => {
    const bot = new SolanaAutoRegister();
    await bot.run();
})().catch((err) => {
    console.error(chalk.red('💥 [FATAL] Uncaught error:'), err.message);
});
