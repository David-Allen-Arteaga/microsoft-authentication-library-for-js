/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import { generateCacheKey, getBrowserStorage } from "./CacheHelpers.js";
import { IWindowStorage } from "./IWindowStorage.js";
import { CacheOptions } from "../config/Configuration.js";
import { Constants, PersistentCacheKeys, TokenKeys } from "@azure/msal-common/browser";
import { MemoryStorage } from "./MemoryStorage.js";
import { BrowserCacheLocation, StaticCacheKeys } from "../utils/BrowserConstants.js";
import { CookieStorage } from "./CookieStorage.js";
import { LocalStorage } from "./LocalStorage.js";
import { createNewGuid, decrypt, encrypt, generateBaseKey, generateHKDF } from "../crypto/BrowserCrypto.js";
import { base64DecToArr } from "../encode/Base64Decode.js";
import { urlEncodeArr } from "../encode/Base64Encode.js";

const ENCRYPTION_KEY = "msal.cache.encryption";

type EncryptionCookie = {
    id: string,
    key: CryptoKey
}

type EncryptedData = {
    id: string,
    nonce: string,
    data: string
}

export class PersistentCache {
    private clientId: string;
    private storage: IWindowStorage<string>;
    private encryptedStorage?: LocalStorage;
    private encryptionCookie?: EncryptionCookie;

    constructor(clientId: string, config: Required<CacheOptions>) {
        this.clientId = clientId;

        if (config.cacheLocation === BrowserCacheLocation.LocalStorage) {
            this.storage = new MemoryStorage(); // Cache reads will come from unencrypted, in-memory store
            this.encryptedStorage = new LocalStorage(); // Cache writes will write to both storage above & encrypt in localStorage
        } else {
            this.storage = getBrowserStorage(config.cacheLocation);
        }
    }

    async initialize(): Promise<void> {
        if (!this.encryptedStorage) {
            return;
        }

        const cookies = new CookieStorage();
        const cookieString = cookies.getItem(ENCRYPTION_KEY);
        let parsedCookie = { key: "", id: ""};
        if (cookieString) {
            try {
                parsedCookie = JSON.parse(cookieString);
            } catch (e){
                // TODO: Log telemetry but don't throw
            }
        }
        if (parsedCookie.key && parsedCookie.id) {
            // Encryption key already exists, import
            this.encryptionCookie = {
                id: parsedCookie.id,
                key: await generateHKDF(base64DecToArr(parsedCookie.key))
            }
        } else {
            // Encryption key doesn't exist or is invalid, generate a new one
            const id = createNewGuid();
            const baseKey = await generateBaseKey();
            const keyStr = urlEncodeArr(new Uint8Array(baseKey));
            this.encryptionCookie = {
                id: id,
                key: await generateHKDF(baseKey)
            };
    
            const cookieData = {
                id:id, 
                key:keyStr
            }
            cookies.setItem(ENCRYPTION_KEY, JSON.stringify(cookieData));
        }

        await this.importExistingCache();
    }

    getItem(key: string): string | null {
        return this.storage.getItem(key);
    }

    async setItem(key: string, value: string): Promise<void> {
        this.storage.setItem(key, value);

        if (this.encryptionCookie && this.encryptedStorage) {
            const {data, nonce} = await encrypt(this.encryptionCookie.key, value);

            const encryptedData: EncryptedData = {id: this.encryptionCookie.id, nonce: nonce, data: data};
            this.encryptedStorage.setItem(key, JSON.stringify(encryptedData));
        }
    }

    removeItem(key: string): void {
        this.storage.removeItem(key);
        this.encryptedStorage?.removeItem(key);
    }

    clear(): void {
        // Removes all remaining MSAL cache items
        this.storage.getKeys().forEach((cacheKey: string) => {
            if (
                cacheKey.startsWith(Constants.CACHE_PREFIX) ||
                cacheKey.indexOf(this.clientId) !== -1
            ) {
                this.storage.removeItem(cacheKey);
                this.encryptedStorage?.removeItem(cacheKey);
            }
        });
    }

    private async importExistingCache(): Promise<void> {
        if (!this.encryptedStorage) {
            return;
        }

        await this.importAccounts();
        await this.importTokens();
    }

    private async importAccounts(): Promise<void> {
        const accountKeyStr = await this.getItemFromEncryptedCache(StaticCacheKeys.ACCOUNT_KEYS);
        if (accountKeyStr) {
            let accountKeys: Array<string> = [];
            try {
                accountKeys = JSON.parse(accountKeyStr);
                this.storage.setItem(StaticCacheKeys.ACCOUNT_KEYS, accountKeyStr);
                await this.importArray(accountKeys);
            } catch(e) {
                // TODO: Log telemetry, don't throw
            }
        }

        const activeAccountKey = generateCacheKey(
            PersistentCacheKeys.ACTIVE_ACCOUNT_FILTERS,
            this.clientId
        );
        const activeAccount = await this.getItemFromEncryptedCache(activeAccountKey);
        if (activeAccount) {
            this.storage.setItem(activeAccountKey, activeAccount);
        }
    }

    private async importTokens(): Promise<void> {
        const tkKey = `${StaticCacheKeys.TOKEN_KEYS}.${this.clientId}`
        const tokenKeyStr = await this.getItemFromEncryptedCache(tkKey);
        if (tokenKeyStr) {
            let tokenKeys: TokenKeys;
            try {
                tokenKeys = JSON.parse(tokenKeyStr);
                this.storage.setItem(tkKey, tokenKeyStr);

                await Promise.all([this.importArray(tokenKeys.idToken), this.importArray(tokenKeys.accessToken), this.importArray(tokenKeys.refreshToken)]);
            } catch(e) {
                // TODO: Log telemetry, don't throw
            }
        }
    }

    private async importArray(arr: Array<string>): Promise<void> {
        const promiseArr: Array<Promise<void>> = [];
        arr.forEach((key) => {
            const promise = this.getItemFromEncryptedCache(key).then((value) => {
                if (value) {
                    this.storage.setItem(key, value);
                }
            });
            promiseArr.push(promise);
        });
        
        await Promise.all(promiseArr);
    }

    private async getItemFromEncryptedCache(key: string): Promise<string | null> {
        if (!this.encryptedStorage || !this.encryptionCookie) {
            return null;
        }

        const rawCache = this.encryptedStorage.getItem(key);
        if (!rawCache) {
            return null;
        }

        let encObj: EncryptedData;
        try {
            encObj = JSON.parse(rawCache);
            if (!encObj.id || !encObj.nonce || !encObj.data) {
                throw "Not encrypted!" // TODO: Typed error
            }

            if (encObj.id !== this.encryptionCookie.id) {
                throw "Old item!" // TODO: Typed error
            }
        } catch (e) {
            // Not a valid encrypted object, remove
            this.encryptedStorage?.removeItem(key);
            return null;
        }

        return decrypt(this.encryptionCookie.key, encObj.nonce, encObj.data);
    }
}
