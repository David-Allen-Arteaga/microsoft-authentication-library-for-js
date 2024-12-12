/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import { Constants } from "@azure/msal-common/browser";
import { generateCacheKey, getBrowserStorage } from "./CacheHelpers.js";
import { CookieStorage } from "./CookieStorage.js";
import { IWindowStorage } from "./IWindowStorage.js";
import { CacheOptions } from "../config/Configuration.js";
import { TemporaryCacheKeys } from "../utils/BrowserConstants.js";
import { BrowserAuthErrorCodes, createBrowserAuthError } from "../error/BrowserAuthError.js";

const INTERACTION_IN_PROGRESS_KEY = `${Constants.CACHE_PREFIX}.${TemporaryCacheKeys.INTERACTION_STATUS_KEY}`;

export class TemporaryCache {
    private clientId: string;
    private useCookies: boolean;
    private secureCookies: boolean;
    private storage: IWindowStorage<string>;

    constructor(clientId: string, config: Required<CacheOptions>) {
        this.clientId = clientId;
        this.useCookies = config.storeAuthStateInCookie;
        this.secureCookies = config.secureCookies;
        this.storage = getBrowserStorage(config.temporaryCacheLocation);
    }

    getItem(baseKey: string): string | null {
        const key = generateCacheKey(baseKey, this.clientId);
        const item = this.storage.getItem(key);
        if (item || !this.useCookies) {
            return item;
        } else {
            const cookies = new CookieStorage();
            return cookies.getItem(key);
        }
    }

    setItem(baseKey: string, value: string): void {
        const key = generateCacheKey(baseKey, this.clientId);
        this.storage.setItem(key, value);
        if (this.useCookies) {
            const cookies = new CookieStorage();
            cookies.setItem(
                key,
                value,
                undefined,
                this.secureCookies
            );
        }
    }

    removeItem(baseKey: string): void {
        const key = generateCacheKey(baseKey, this.clientId);
        this.storage.removeItem(key);
        if (this.useCookies) {
            const cookies = new CookieStorage();
            cookies.removeItem(key);
        }
    }

    clear(): void {
        Object.values(TemporaryCacheKeys).forEach(baseKey => {
            this.removeItem(baseKey);
        });
        this.setInteractionInProgress(false);
    }

    isInteractionInProgress(matchClientId?: boolean): boolean {
        const clientId = this.getItem(INTERACTION_IN_PROGRESS_KEY);

        if (matchClientId) {
            return clientId === this.clientId;
        } else {
            return !!clientId;
        }
    }

    setInteractionInProgress(inProgress: boolean): void {
        // Ensure we don't overwrite interaction in progress for a different clientId
        if (inProgress) {
            if (this.getItem(INTERACTION_IN_PROGRESS_KEY)) {
                throw createBrowserAuthError(
                    BrowserAuthErrorCodes.interactionInProgress
                );
            } else {
                // No interaction is in progress
                this.setItem(`${Constants.CACHE_PREFIX}.${TemporaryCacheKeys.INTERACTION_STATUS_KEY}`, this.clientId);
            }
        } else if (
            !inProgress &&
            this.getItem(INTERACTION_IN_PROGRESS_KEY) === this.clientId
        ) {
            this.removeItem(`${Constants.CACHE_PREFIX}.${TemporaryCacheKeys.INTERACTION_STATUS_KEY}`);
        }
    }
}
