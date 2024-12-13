/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import {
    Constants,
    PersistentCacheKeys,
    ICrypto,
    AccountEntity,
    IdTokenEntity,
    AccessTokenEntity,
    RefreshTokenEntity,
    AppMetadataEntity,
    CacheManager,
    ServerTelemetryEntity,
    ThrottlingEntity,
    Logger,
    AuthorityMetadataEntity,
    DEFAULT_CRYPTO_IMPLEMENTATION,
    AccountInfo,
    ActiveAccountFilters,
    ValidCredentialType,
    TokenKeys,
    CredentialType,
    CacheRecord,
    AuthenticationScheme,
    createClientAuthError,
    ClientAuthErrorCodes,
    PerformanceEvents,
    IPerformanceClient,
    StaticAuthorityOptions,
    CacheHelpers,
    StoreInCache,
    CacheError,
} from "@azure/msal-common/browser";
import { CacheOptions } from "../config/Configuration.js";
import {
    BrowserCacheLocation,
    TemporaryCacheKeys,
    InMemoryCacheKeys,
    StaticCacheKeys,
} from "../utils/BrowserConstants.js";
import { MemoryStorage } from "./MemoryStorage.js";
import { NativeTokenRequest } from "../broker/nativeBroker/NativeRequest.js";
import { AuthenticationResult } from "../response/AuthenticationResult.js";
import { SilentRequest } from "../request/SilentRequest.js";
import { SsoSilentRequest } from "../request/SsoSilentRequest.js";
import { RedirectRequest } from "../request/RedirectRequest.js";
import { PopupRequest } from "../request/PopupRequest.js";
import { base64Decode } from "../encode/Base64Decode.js";
import { TemporaryCache } from "./TemporaryCache.js";
import { generateCacheKey } from "./CacheHelpers.js";
import { PersistentCache } from "./PersistentCache.js";

/**
 * This class implements the cache storage interface for MSAL through browser local or session storage.
 * Cookies are only used if storeAuthStateInCookie is true, and are only used for
 * parameters such as state and nonce, generally.
 */
export class BrowserCacheManager extends CacheManager {
    // Window storage object (either local or sessionStorage)
    protected browserStorage: PersistentCache;
    // Internal in-memory storage object used for data used by msal that does not need to persist across page loads
    protected internalStorage: MemoryStorage<string>;
    // Temporary cache
    protected tempCache: TemporaryCache;
    // Logger instance
    protected logger: Logger;
    // Telemetry perf client
    protected performanceClient?: IPerformanceClient;

    constructor(
        clientId: string,
        cacheConfig: Required<CacheOptions>,
        cryptoImpl: ICrypto,
        logger: Logger,
        staticAuthorityOptions?: StaticAuthorityOptions,
        performanceClient?: IPerformanceClient
    ) {
        super(clientId, cryptoImpl, logger, staticAuthorityOptions);
        this.logger = logger;
        this.internalStorage = new MemoryStorage();
        this.browserStorage = new PersistentCache(clientId, cacheConfig);
        this.tempCache = new TemporaryCache(clientId, cacheConfig);
        this.performanceClient = performanceClient;
    }

    async initialize(): Promise<void> {
        await this.browserStorage.initialize();
    }

    /**
     * Parses passed value as JSON object, JSON.parse() will throw an error.
     * @param input
     */
    protected validateAndParseJson(jsonValue: string): object | null {
        try {
            const parsedJson = JSON.parse(jsonValue);
            /**
             * There are edge cases in which JSON.parse will successfully parse a non-valid JSON object
             * (e.g. JSON.parse will parse an escaped string into an unescaped string), so adding a type check
             * of the parsed value is necessary in order to be certain that the string represents a valid JSON object.
             *
             */
            return parsedJson && typeof parsedJson === "object"
                ? parsedJson
                : null;
        } catch (error) {
            return null;
        }
    }

    /**
     * fetches the entry from the browser storage based off the key
     * @param key
     */
    getItem(key: string): string | null {
        return this.browserStorage.getItem(key);
    }

    /**
     * sets the entry in the browser storage
     * @param key
     * @param value
     */
    async setItem(key: string, value: string): Promise<void> {
        await this.browserStorage.setItem(key, value);
    }

    /**
     * fetch the account entity from the platform cache
     * @param accountKey
     */
    getAccount(accountKey: string): AccountEntity | null {
        this.logger.trace("BrowserCacheManager.getAccount called");
        return this.getCachedAccountEntity(accountKey);
    }

    /**
     * Reads account from cache, deserializes it into an account entity and returns it.
     * If account is not found from the key, returns null and removes key from map.
     * @param accountKey
     * @returns
     */
    getCachedAccountEntity(accountKey: string): AccountEntity | null {
        const serializedAccount = this.getItem(accountKey);
        if (!serializedAccount) {
            return null;
        }

        const parsedAccount = this.validateAndParseJson(serializedAccount);
        if (!parsedAccount || !AccountEntity.isAccountEntity(parsedAccount)) {
            return null;
        }

        return CacheManager.toObject<AccountEntity>(
            new AccountEntity(),
            parsedAccount
        );
    }

    /**
     * set account entity in the platform cache
     * @param account
     */
    async setAccount(account: AccountEntity): Promise<void> {
        this.logger.trace("BrowserCacheManager.setAccount called");
        const key = account.generateAccountKey();
        await this.setItem(key, JSON.stringify(account));
        await this.addAccountKeyToMap(key);
    }

    /**
     * Returns the array of account keys currently cached
     * @returns
     */
    getAccountKeys(): Array<string> {
        this.logger.trace("BrowserCacheManager.getAccountKeys called");
        const accountKeys = this.getItem(StaticCacheKeys.ACCOUNT_KEYS);
        if (accountKeys) {
            return JSON.parse(accountKeys);
        }

        this.logger.verbose(
            "BrowserCacheManager.getAccountKeys - No account keys found"
        );
        return [];
    }

    /**
     * Add a new account to the key map
     * @param key
     */
    async addAccountKeyToMap(key: string): Promise<void> {
        this.logger.trace("BrowserCacheManager.addAccountKeyToMap called");
        this.logger.tracePii(
            `BrowserCacheManager.addAccountKeyToMap called with key: ${key}`
        );
        const accountKeys = this.getAccountKeys();
        if (accountKeys.indexOf(key) === -1) {
            // Only add key if it does not already exist in the map
            accountKeys.push(key);
            await this.setItem(
                StaticCacheKeys.ACCOUNT_KEYS,
                JSON.stringify(accountKeys)
            );
            this.logger.verbose(
                "BrowserCacheManager.addAccountKeyToMap account key added"
            );
        } else {
            this.logger.verbose(
                "BrowserCacheManager.addAccountKeyToMap account key already exists in map"
            );
        }
    }

    /**
     * Remove an account from the key map
     * @param key
     */
    async removeAccountKeyFromMap(key: string): Promise<void> {
        this.logger.trace("BrowserCacheManager.removeAccountKeyFromMap called");
        this.logger.tracePii(
            `BrowserCacheManager.removeAccountKeyFromMap called with key: ${key}`
        );
        const accountKeys = this.getAccountKeys();
        const removalIndex = accountKeys.indexOf(key);
        if (removalIndex > -1) {
            accountKeys.splice(removalIndex, 1);
            await this.setItem(
                StaticCacheKeys.ACCOUNT_KEYS,
                JSON.stringify(accountKeys)
            );
            this.logger.trace(
                "BrowserCacheManager.removeAccountKeyFromMap account key removed"
            );
        } else {
            this.logger.trace(
                "BrowserCacheManager.removeAccountKeyFromMap key not found in existing map"
            );
        }
    }

    /**
     * Extends inherited removeAccount function to include removal of the account key from the map
     * @param key
     */
    async removeAccount(key: string): Promise<void> {
        await super.removeAccount(key);
        await this.removeAccountKeyFromMap(key);
    }

    /**
     * Remove account entity from the platform cache if it's outdated
     * @param accountKey
     */
    async removeOutdatedAccount(accountKey: string): Promise<void> {
        this.removeItem(accountKey);
        await this.removeAccountKeyFromMap(accountKey);
    }

    /**
     * Removes given idToken from the cache and from the key map
     * @param key
     */
    async removeIdToken(key: string): Promise<void> {
        super.removeIdToken(key);
        await this.removeTokenKey(key, CredentialType.ID_TOKEN);
    }

    /**
     * Removes given accessToken from the cache and from the key map
     * @param key
     */
    async removeAccessToken(key: string): Promise<void> {
        void super.removeAccessToken(key);
        await this.removeTokenKey(key, CredentialType.ACCESS_TOKEN);
    }

    /**
     * Removes given refreshToken from the cache and from the key map
     * @param key
     */
    async removeRefreshToken(key: string): Promise<void> {
        super.removeRefreshToken(key);
        await this.removeTokenKey(key, CredentialType.REFRESH_TOKEN);
    }

    /**
     * Gets the keys for the cached tokens associated with this clientId
     * @returns
     */
    getTokenKeys(): TokenKeys {
        this.logger.trace("BrowserCacheManager.getTokenKeys called");
        const item = this.getItem(
            `${StaticCacheKeys.TOKEN_KEYS}.${this.clientId}`
        );
        if (item) {
            const tokenKeys = this.validateAndParseJson(item);
            if (
                tokenKeys &&
                tokenKeys.hasOwnProperty("idToken") &&
                tokenKeys.hasOwnProperty("accessToken") &&
                tokenKeys.hasOwnProperty("refreshToken")
            ) {
                return tokenKeys as TokenKeys;
            } else {
                this.logger.error(
                    "BrowserCacheManager.getTokenKeys - Token keys found but in an unknown format. Returning empty key map."
                );
            }
        } else {
            this.logger.verbose(
                "BrowserCacheManager.getTokenKeys - No token keys found"
            );
        }

        return {
            idToken: [],
            accessToken: [],
            refreshToken: [],
        };
    }

    /**
     * Adds the given key to the token key map
     * @param key
     * @param type
     */
    async addTokenKey(key: string, type: CredentialType): Promise<void> {
        this.logger.trace("BrowserCacheManager addTokenKey called");
        const tokenKeys = this.getTokenKeys();

        switch (type) {
            case CredentialType.ID_TOKEN:
                if (tokenKeys.idToken.indexOf(key) === -1) {
                    this.logger.info(
                        "BrowserCacheManager: addTokenKey - idToken added to map"
                    );
                    tokenKeys.idToken.push(key);
                }
                break;
            case CredentialType.ACCESS_TOKEN:
                if (tokenKeys.accessToken.indexOf(key) === -1) {
                    this.logger.info(
                        "BrowserCacheManager: addTokenKey - accessToken added to map"
                    );
                    tokenKeys.accessToken.push(key);
                }
                break;
            case CredentialType.REFRESH_TOKEN:
                if (tokenKeys.refreshToken.indexOf(key) === -1) {
                    this.logger.info(
                        "BrowserCacheManager: addTokenKey - refreshToken added to map"
                    );
                    tokenKeys.refreshToken.push(key);
                }
                break;
            default:
                this.logger.error(
                    `BrowserCacheManager:addTokenKey - CredentialType provided invalid. CredentialType: ${type}`
                );
                throw createClientAuthError(
                    ClientAuthErrorCodes.unexpectedCredentialType
                );
        }

        await this.setItem(
            `${StaticCacheKeys.TOKEN_KEYS}.${this.clientId}`,
            JSON.stringify(tokenKeys)
        );
    }

    /**
     * Removes the given key from the token key map
     * @param key
     * @param type
     */
    async removeTokenKey(key: string, type: CredentialType): Promise<void> {
        this.logger.trace("BrowserCacheManager removeTokenKey called");
        const tokenKeys = this.getTokenKeys();

        switch (type) {
            case CredentialType.ID_TOKEN:
                this.logger.infoPii(
                    `BrowserCacheManager: removeTokenKey - attempting to remove idToken with key: ${key} from map`
                );
                const idRemoval = tokenKeys.idToken.indexOf(key);
                if (idRemoval > -1) {
                    this.logger.info(
                        "BrowserCacheManager: removeTokenKey - idToken removed from map"
                    );
                    tokenKeys.idToken.splice(idRemoval, 1);
                } else {
                    this.logger.info(
                        "BrowserCacheManager: removeTokenKey - idToken does not exist in map. Either it was previously removed or it was never added."
                    );
                }
                break;
            case CredentialType.ACCESS_TOKEN:
                this.logger.infoPii(
                    `BrowserCacheManager: removeTokenKey - attempting to remove accessToken with key: ${key} from map`
                );
                const accessRemoval = tokenKeys.accessToken.indexOf(key);
                if (accessRemoval > -1) {
                    this.logger.info(
                        "BrowserCacheManager: removeTokenKey - accessToken removed from map"
                    );
                    tokenKeys.accessToken.splice(accessRemoval, 1);
                } else {
                    this.logger.info(
                        "BrowserCacheManager: removeTokenKey - accessToken does not exist in map. Either it was previously removed or it was never added."
                    );
                }
                break;
            case CredentialType.REFRESH_TOKEN:
                this.logger.infoPii(
                    `BrowserCacheManager: removeTokenKey - attempting to remove refreshToken with key: ${key} from map`
                );
                const refreshRemoval = tokenKeys.refreshToken.indexOf(key);
                if (refreshRemoval > -1) {
                    this.logger.info(
                        "BrowserCacheManager: removeTokenKey - refreshToken removed from map"
                    );
                    tokenKeys.refreshToken.splice(refreshRemoval, 1);
                } else {
                    this.logger.info(
                        "BrowserCacheManager: removeTokenKey - refreshToken does not exist in map. Either it was previously removed or it was never added."
                    );
                }
                break;
            default:
                this.logger.error(
                    `BrowserCacheManager:removeTokenKey - CredentialType provided invalid. CredentialType: ${type}`
                );
                throw createClientAuthError(
                    ClientAuthErrorCodes.unexpectedCredentialType
                );
        }

        await this.setItem(
            `${StaticCacheKeys.TOKEN_KEYS}.${this.clientId}`,
            JSON.stringify(tokenKeys)
        );
    }

    /**
     * generates idToken entity from a string
     * @param idTokenKey
     */
    getIdTokenCredential(idTokenKey: string): IdTokenEntity | null {
        const value = this.getItem(idTokenKey);
        if (!value) {
            this.logger.trace(
                "BrowserCacheManager.getIdTokenCredential: called, no cache hit"
            );
            return null;
        }

        const parsedIdToken = this.validateAndParseJson(value);
        if (!parsedIdToken || !CacheHelpers.isIdTokenEntity(parsedIdToken)) {
            this.logger.trace(
                "BrowserCacheManager.getIdTokenCredential: called, no cache hit"
            );
            return null;
        }

        this.logger.trace(
            "BrowserCacheManager.getIdTokenCredential: cache hit"
        );
        return parsedIdToken as IdTokenEntity;
    }

    /**
     * set IdToken credential to the platform cache
     * @param idToken
     */
    async setIdTokenCredential(idToken: IdTokenEntity): Promise<void> {
        this.logger.trace("BrowserCacheManager.setIdTokenCredential called");
        const idTokenKey = CacheHelpers.generateCredentialKey(idToken);

        await this.setItem(idTokenKey, JSON.stringify(idToken));
        await this.addTokenKey(idTokenKey, CredentialType.ID_TOKEN);
    }

    /**
     * generates accessToken entity from a string
     * @param key
     */
    getAccessTokenCredential(accessTokenKey: string): AccessTokenEntity | null {
        const value = this.getItem(accessTokenKey);
        if (!value) {
            this.logger.trace(
                "BrowserCacheManager.getAccessTokenCredential: called, no cache hit"
            );
            return null;
        }
        const parsedAccessToken = this.validateAndParseJson(value);
        if (
            !parsedAccessToken ||
            !CacheHelpers.isAccessTokenEntity(parsedAccessToken)
        ) {
            this.logger.trace(
                "BrowserCacheManager.getAccessTokenCredential: called, no cache hit"
            );
            return null;
        }

        this.logger.trace(
            "BrowserCacheManager.getAccessTokenCredential: cache hit"
        );
        return parsedAccessToken as AccessTokenEntity;
    }

    /**
     * set accessToken credential to the platform cache
     * @param accessToken
     */
    async setAccessTokenCredential(accessToken: AccessTokenEntity): Promise<void> {
        this.logger.trace(
            "BrowserCacheManager.setAccessTokenCredential called"
        );
        const accessTokenKey = CacheHelpers.generateCredentialKey(accessToken);
        await this.setItem(accessTokenKey, JSON.stringify(accessToken));

        await this.addTokenKey(accessTokenKey, CredentialType.ACCESS_TOKEN);
    }

    /**
     * generates refreshToken entity from a string
     * @param refreshTokenKey
     */
    getRefreshTokenCredential(
        refreshTokenKey: string
    ): RefreshTokenEntity | null {
        const value = this.getItem(refreshTokenKey);
        if (!value) {
            this.logger.trace(
                "BrowserCacheManager.getRefreshTokenCredential: called, no cache hit"
            );
            return null;
        }
        const parsedRefreshToken = this.validateAndParseJson(value);
        if (
            !parsedRefreshToken ||
            !CacheHelpers.isRefreshTokenEntity(parsedRefreshToken)
        ) {
            this.logger.trace(
                "BrowserCacheManager.getRefreshTokenCredential: called, no cache hit"
            );
            return null;
        }

        this.logger.trace(
            "BrowserCacheManager.getRefreshTokenCredential: cache hit"
        );
        return parsedRefreshToken as RefreshTokenEntity;
    }

    /**
     * set refreshToken credential to the platform cache
     * @param refreshToken
     */
    async setRefreshTokenCredential(refreshToken: RefreshTokenEntity): Promise<void> {
        this.logger.trace(
            "BrowserCacheManager.setRefreshTokenCredential called"
        );
        const refreshTokenKey =
            CacheHelpers.generateCredentialKey(refreshToken);
        await this.setItem(refreshTokenKey, JSON.stringify(refreshToken));

        await this.addTokenKey(refreshTokenKey, CredentialType.REFRESH_TOKEN);
    }

    /**
     * fetch appMetadata entity from the platform cache
     * @param appMetadataKey
     */
    getAppMetadata(appMetadataKey: string): AppMetadataEntity | null {
        const value = this.getItem(appMetadataKey);
        if (!value) {
            this.logger.trace(
                "BrowserCacheManager.getAppMetadata: called, no cache hit"
            );
            return null;
        }

        const parsedMetadata = this.validateAndParseJson(value);
        if (
            !parsedMetadata ||
            !CacheHelpers.isAppMetadataEntity(appMetadataKey, parsedMetadata)
        ) {
            this.logger.trace(
                "BrowserCacheManager.getAppMetadata: called, no cache hit"
            );
            return null;
        }

        this.logger.trace("BrowserCacheManager.getAppMetadata: cache hit");
        return parsedMetadata as AppMetadataEntity;
    }

    /**
     * set appMetadata entity to the platform cache
     * @param appMetadata
     */
    async setAppMetadata(appMetadata: AppMetadataEntity): Promise<void> {
        this.logger.trace("BrowserCacheManager.setAppMetadata called");
        const appMetadataKey = CacheHelpers.generateAppMetadataKey(appMetadata);
        await this.setItem(appMetadataKey, JSON.stringify(appMetadata));
    }

    /**
     * fetch server telemetry entity from the platform cache
     * @param serverTelemetryKey
     */
    getServerTelemetry(
        serverTelemetryKey: string
    ): ServerTelemetryEntity | null {
        const value = this.getItem(serverTelemetryKey);
        if (!value) {
            this.logger.trace(
                "BrowserCacheManager.getServerTelemetry: called, no cache hit"
            );
            return null;
        }
        const parsedEntity = this.validateAndParseJson(value);
        if (
            !parsedEntity ||
            !CacheHelpers.isServerTelemetryEntity(
                serverTelemetryKey,
                parsedEntity
            )
        ) {
            this.logger.trace(
                "BrowserCacheManager.getServerTelemetry: called, no cache hit"
            );
            return null;
        }

        this.logger.trace("BrowserCacheManager.getServerTelemetry: cache hit");
        return parsedEntity as ServerTelemetryEntity;
    }

    /**
     * set server telemetry entity to the platform cache
     * @param serverTelemetryKey
     * @param serverTelemetry
     */
    async setServerTelemetry(
        serverTelemetryKey: string,
        serverTelemetry: ServerTelemetryEntity
    ): Promise<void> {
        this.logger.trace("BrowserCacheManager.setServerTelemetry called");
        await this.setItem(serverTelemetryKey, JSON.stringify(serverTelemetry));
    }

    /**
     *
     */
    getAuthorityMetadata(key: string): AuthorityMetadataEntity | null {
        const value = this.internalStorage.getItem(key);
        if (!value) {
            this.logger.trace(
                "BrowserCacheManager.getAuthorityMetadata: called, no cache hit"
            );
            return null;
        }
        const parsedMetadata = this.validateAndParseJson(value);
        if (
            parsedMetadata &&
            CacheHelpers.isAuthorityMetadataEntity(key, parsedMetadata)
        ) {
            this.logger.trace(
                "BrowserCacheManager.getAuthorityMetadata: cache hit"
            );
            return parsedMetadata as AuthorityMetadataEntity;
        }
        return null;
    }

    /**
     *
     */
    getAuthorityMetadataKeys(): Array<string> {
        const allKeys = this.internalStorage.getKeys();
        return allKeys.filter((key) => {
            return this.isAuthorityMetadata(key);
        });
    }

    /**
     * Sets wrapper metadata in memory
     * @param wrapperSKU
     * @param wrapperVersion
     */
    setWrapperMetadata(wrapperSKU: string, wrapperVersion: string): void {
        this.internalStorage.setItem(InMemoryCacheKeys.WRAPPER_SKU, wrapperSKU);
        this.internalStorage.setItem(
            InMemoryCacheKeys.WRAPPER_VER,
            wrapperVersion
        );
    }

    /**
     * Returns wrapper metadata from in-memory storage
     */
    getWrapperMetadata(): [string, string] {
        const sku =
            this.internalStorage.getItem(InMemoryCacheKeys.WRAPPER_SKU) ||
            Constants.EMPTY_STRING;
        const version =
            this.internalStorage.getItem(InMemoryCacheKeys.WRAPPER_VER) ||
            Constants.EMPTY_STRING;
        return [sku, version];
    }

    /**
     *
     * @param entity
     */
    setAuthorityMetadata(key: string, entity: AuthorityMetadataEntity): void {
        this.logger.trace("BrowserCacheManager.setAuthorityMetadata called");
        this.internalStorage.setItem(key, JSON.stringify(entity));
    }

    /**
     * Gets the active account
     */
    getActiveAccount(): AccountInfo | null {
        const activeAccountKeyFilters = generateCacheKey(
            PersistentCacheKeys.ACTIVE_ACCOUNT_FILTERS,
            this.clientId
        );
        const activeAccountValueFilters = this.getItem(activeAccountKeyFilters);
        if (!activeAccountValueFilters) {
            this.logger.trace(
                "BrowserCacheManager.getActiveAccount: No active account found"
            );
            return null;
        }
        const activeAccountValueObj = this.validateAndParseJson(
            activeAccountValueFilters
        ) as AccountInfo;
        if (activeAccountValueObj) {
            this.logger.trace(
                "BrowserCacheManager.getActiveAccount: Active account filters schema found"
            );
            return this.getAccountInfoFilteredBy({
                homeAccountId: activeAccountValueObj.homeAccountId,
                localAccountId: activeAccountValueObj.localAccountId,
                tenantId: activeAccountValueObj.tenantId,
            });
        }
        this.logger.trace(
            "BrowserCacheManager.getActiveAccount: No active account found"
        );
        return null;
    }

    /**
     * Sets the active account's localAccountId in cache
     * @param account
     */
    async setActiveAccount(account: AccountInfo | null): Promise<void> {
        const activeAccountKey = generateCacheKey(
            PersistentCacheKeys.ACTIVE_ACCOUNT_FILTERS,
            this.clientId
        );
        if (account) {
            this.logger.verbose("setActiveAccount: Active account set");
            const activeAccountValue: ActiveAccountFilters = {
                homeAccountId: account.homeAccountId,
                localAccountId: account.localAccountId,
                tenantId: account.tenantId,
            };
            await this.browserStorage.setItem(
                activeAccountKey,
                JSON.stringify(activeAccountValue)
            );
            
        } else {
            this.logger.verbose(
                "setActiveAccount: No account passed, active account not set"
            );
            this.browserStorage.removeItem(activeAccountKey);
        }
    }

    /**
     * fetch throttling entity from the platform cache
     * @param throttlingCacheKey
     */
    getThrottlingCache(throttlingCacheKey: string): ThrottlingEntity | null {
        const value = this.getItem(throttlingCacheKey);
        if (!value) {
            this.logger.trace(
                "BrowserCacheManager.getThrottlingCache: called, no cache hit"
            );
            return null;
        }

        const parsedThrottlingCache = this.validateAndParseJson(value);
        if (
            !parsedThrottlingCache ||
            !CacheHelpers.isThrottlingEntity(
                throttlingCacheKey,
                parsedThrottlingCache
            )
        ) {
            this.logger.trace(
                "BrowserCacheManager.getThrottlingCache: called, no cache hit"
            );
            return null;
        }

        this.logger.trace("BrowserCacheManager.getThrottlingCache: cache hit");
        return parsedThrottlingCache as ThrottlingEntity;
    }

    /**
     * set throttling entity to the platform cache
     * @param throttlingCacheKey
     * @param throttlingCache
     */
    async setThrottlingCache(
        throttlingCacheKey: string,
        throttlingCache: ThrottlingEntity
    ): Promise<void> {
        this.logger.trace("BrowserCacheManager.setThrottlingCache called");
        await this.setItem(throttlingCacheKey, JSON.stringify(throttlingCache));
    }

    /**
     * Removes the cache item with the given key.
     * @param key
     */
    removeItem(key: string): void {
        this.browserStorage.removeItem(key);
    }

    /**
     * Clears all cache entries created by MSAL.
     */
    async clear(): Promise<void> {
        // Removes all accounts and their credentials
        await this.removeAllAccounts();

        // Remove temp storage first to make sure any cookies are cleared
        this.tempCache.clear();
        this.browserStorage.clear();
        this.internalStorage.clear();
    }

    /**
     * Clears all access tokes that have claims prior to saving the current one
     * @param performanceClient {IPerformanceClient}
     * @param correlationId {string} correlation id
     * @returns
     */
    async clearTokensAndKeysWithClaims(
        performanceClient: IPerformanceClient,
        correlationId: string
    ): Promise<void> {
        performanceClient.addQueueMeasurement(
            PerformanceEvents.ClearTokensAndKeysWithClaims,
            correlationId
        );

        const tokenKeys = this.getTokenKeys();

        const removedAccessTokens: Array<Promise<void>> = [];
        tokenKeys.accessToken.forEach((key: string) => {
            // if the access token has claims in its key, remove the token key and the token
            const credential = this.getAccessTokenCredential(key);
            if (
                credential?.requestedClaimsHash &&
                key.includes(credential.requestedClaimsHash.toLowerCase())
            ) {
                removedAccessTokens.push(this.removeAccessToken(key));
            }
        });
        await Promise.all(removedAccessTokens);

        // warn if any access tokens are removed
        if (removedAccessTokens.length > 0) {
            this.logger.warning(
                `${removedAccessTokens.length} access tokens with claims in the cache keys have been removed from the cache.`
            );
        }
    }

    /**
     * Gets cached native request for redirect flows
     */
    getCachedNativeRequest(): NativeTokenRequest | null {
        this.logger.trace("BrowserCacheManager.getCachedNativeRequest called");
        const cachedRequest = this.tempCache.getItem(
            TemporaryCacheKeys.NATIVE_REQUEST
        );
        if (!cachedRequest) {
            this.logger.trace(
                "BrowserCacheManager.getCachedNativeRequest: No cached native request found"
            );
            return null;
        }

        const parsedRequest = this.validateAndParseJson(
            cachedRequest
        ) as NativeTokenRequest;
        if (!parsedRequest) {
            this.logger.error(
                "BrowserCacheManager.getCachedNativeRequest: Unable to parse native request"
            );
            return null;
        }

        return parsedRequest;
    }

    /**
     * Updates a credential's cache key if the current cache key is outdated
     */
    async updateCredentialCacheKey(
        currentCacheKey: string,
        credential: ValidCredentialType
    ): Promise<string> {
        const updatedCacheKey = CacheHelpers.generateCredentialKey(credential);

        if (currentCacheKey !== updatedCacheKey) {
            const cacheItem = this.getItem(currentCacheKey);
            if (cacheItem) {
                this.browserStorage.removeItem(currentCacheKey);
                await this.setItem(updatedCacheKey, cacheItem);
                this.logger.verbose(
                    `Updated an outdated ${credential.credentialType} cache key`
                );
                return updatedCacheKey;
            } else {
                this.logger.error(
                    `Attempted to update an outdated ${credential.credentialType} cache key but no item matching the outdated key was found in storage`
                );
            }
        }

        return currentCacheKey;
    }

    /**
     * Builds credential entities from AuthenticationResult object and saves the resulting credentials to the cache
     * @param result
     * @param request
     */
    async hydrateCache(
        result: AuthenticationResult,
        request:
            | SilentRequest
            | SsoSilentRequest
            | RedirectRequest
            | PopupRequest
    ): Promise<void> {
        const idTokenEntity = CacheHelpers.createIdTokenEntity(
            result.account?.homeAccountId,
            result.account?.environment,
            result.idToken,
            this.clientId,
            result.tenantId
        );

        let claimsHash;
        if (request.claims) {
            claimsHash = await this.cryptoImpl.hashString(request.claims);
        }

        /**
         * meta data for cache stores time in seconds from epoch
         * AuthenticationResult returns expiresOn and extExpiresOn in milliseconds (as a Date object which is in ms)
         * We need to map these for the cache when building tokens from AuthenticationResult
         *
         * The next MSAL VFuture should map these both to same value if possible
         */

        const accessTokenEntity = CacheHelpers.createAccessTokenEntity(
            result.account?.homeAccountId,
            result.account.environment,
            result.accessToken,
            this.clientId,
            result.tenantId,
            result.scopes.join(" "),
            result.expiresOn ? result.expiresOn.getTime() / 1000 : 0,
            result.extExpiresOn ? result.extExpiresOn.getTime() / 1000 : 0,
            base64Decode,
            undefined, // refreshOn
            result.tokenType as AuthenticationScheme,
            undefined, // userAssertionHash
            request.sshKid,
            request.claims,
            claimsHash
        );

        const cacheRecord = {
            idToken: idTokenEntity,
            accessToken: accessTokenEntity,
        };
        return this.saveCacheRecord(cacheRecord);
    }

    /**
     * saves a cache record
     * @param cacheRecord {CacheRecord}
     * @param storeInCache {?StoreInCache}
     * @param correlationId {?string} correlation id
     */
    async saveCacheRecord(
        cacheRecord: CacheRecord,
        storeInCache?: StoreInCache,
        correlationId?: string
    ): Promise<void> {
        try {
            await super.saveCacheRecord(
                cacheRecord,
                storeInCache,
                correlationId
            );
        } catch (e) {
            if (
                e instanceof CacheError &&
                this.performanceClient &&
                correlationId
            ) {
                try {
                    const tokenKeys = this.getTokenKeys();

                    this.performanceClient.addFields(
                        {
                            cacheRtCount: tokenKeys.refreshToken.length,
                            cacheIdCount: tokenKeys.idToken.length,
                            cacheAtCount: tokenKeys.accessToken.length,
                        },
                        correlationId
                    );
                } catch (e) {}
            }

            throw e;
        }
    }
}

export const DEFAULT_BROWSER_CACHE_MANAGER = (
    clientId: string,
    logger: Logger
): BrowserCacheManager => {
    const cacheOptions: Required<CacheOptions> = {
        cacheLocation: BrowserCacheLocation.MemoryStorage,
        temporaryCacheLocation: BrowserCacheLocation.MemoryStorage,
        storeAuthStateInCookie: false,
        secureCookies: false,
        cacheMigrationEnabled: false,
        claimsBasedCachingEnabled: false,
    };
    return new BrowserCacheManager(
        clientId,
        cacheOptions,
        DEFAULT_CRYPTO_IMPLEMENTATION,
        logger
    );
};
