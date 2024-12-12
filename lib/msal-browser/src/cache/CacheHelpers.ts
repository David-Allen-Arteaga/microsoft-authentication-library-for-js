/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import { Constants, Logger } from "@azure/msal-common/browser";
import { BrowserCacheLocation } from "../utils/BrowserConstants.js";
import { IWindowStorage } from "./IWindowStorage.js";
import { LocalStorage } from "./LocalStorage.js";
import { MemoryStorage } from "./MemoryStorage.js";
import { SessionStorage } from "./SessionStorage.js";

/**
 * Returns a window storage class implementing the IWindowStorage interface that corresponds to the configured cacheLocation.
 * @param cacheLocation
 */
export function getBrowserStorage(
    cacheLocation: BrowserCacheLocation | string,
    logger?: Logger
): IWindowStorage<string> {
    try {
        switch (cacheLocation) {
            case BrowserCacheLocation.LocalStorage:
                return new LocalStorage();
            case BrowserCacheLocation.SessionStorage:
                return new SessionStorage();
            case BrowserCacheLocation.MemoryStorage:
            default:
                break;
        }
    } catch (e) {
        logger?.error(e as string);
    }
    return new MemoryStorage<string>();
}

/**
 * Prepend msal.<client-id> to each key;
 * @param key
 * @param addInstanceId
 */
export function generateCacheKey(key: string, clientId: string): string {
    if (key.startsWith(Constants.CACHE_PREFIX)) {
        return key;
    }
    
    return `${Constants.CACHE_PREFIX}.${clientId}.${key}`;
}
