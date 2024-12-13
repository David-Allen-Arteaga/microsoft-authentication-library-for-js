/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import { getBrowserStorage } from "./CacheHelpers.js";
import { IWindowStorage } from "./IWindowStorage.js";
import { CacheOptions } from "../config/Configuration.js";
import { Constants } from "@azure/msal-common/browser";
import { MemoryStorage } from "./MemoryStorage.js";
import { BrowserCacheLocation } from "../utils/BrowserConstants.js";
import { CookieStorage } from "./CookieStorage.js";
import { LocalStorage } from "./LocalStorage.js";
import { createNewGuid, encrypt, exportBaseKey, generateBaseKey, importBaseKey } from "../crypto/BrowserCrypto.js";

const ENCRYPTION_KEY = "msal.cache.encryption";

type EncryptionCookie = {
    id: string,
    key: CryptoKey
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
        if (cookieString) {
            const parsedCookie = JSON.parse(cookieString);
            if (parsedCookie.key && parsedCookie.id) {
                this.encryptionCookie = {
                    id: parsedCookie.id,
                    key: await importBaseKey(parsedCookie.key)
                }
                return;
            }
        }

        const id = createNewGuid();
        const baseKey = await generateBaseKey();
        const keyStr = await exportBaseKey(baseKey);
        this.encryptionCookie = {
            id: id,
            key: baseKey
        };

        const cookieData = {
            id:id, 
            key:keyStr
        }
        cookies.setItem(ENCRYPTION_KEY, JSON.stringify(cookieData));
    }

    getItem(key: string): string | null {
        return this.storage.getItem(key);
    }

    async setItem(key: string, value: string): Promise<void> {
        this.storage.setItem(key, value);

        if (this.encryptionCookie && this.encryptedStorage) {
            const {data, nonce} = await encrypt(this.encryptionCookie.key, value);

            this.encryptedStorage.setItem(key, JSON.stringify({id: this.encryptionCookie.id, nonce: nonce, data: data}));
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
}
