/**
 * acme-client type definitions
 */

import { XiorInstance } from "xior";
import type { webcrypto as webcryptoType } from "crypto";
import * as rfc8555 from "./rfc8555";

type CryptoKey = webcryptoType.CryptoKey;
type CryptoKeyPair = webcryptoType.CryptoKeyPair;

export type PrivateKeyBuffer = Buffer;
export type PublicKeyBuffer = Buffer;
export type CertificateBuffer = Buffer;
export type CsrBuffer = Buffer;

export type WebPrivateKeyBuffer = Uint8Array;
export type WebPublicKeyBuffer = Uint8Array;
export type WebCertificateBuffer = Uint8Array;
export type WebCsrBuffer = Uint8Array;

export type PrivateKeyString = string;
export type PublicKeyString = string;
export type CertificateString = string;
export type CsrString = string;

/**
 * Augmented ACME interfaces
 */

export interface Order extends rfc8555.Order {
    url: string;
}

export interface Authorization extends rfc8555.Authorization {
    url: string;
}

/**
 * Client
 */

export interface ClientOptions {
    directoryUrl: string;
    accountKey: LooseKeyPair;
    accountUrl?: string;
    externalAccountBinding?: ClientExternalAccountBindingOptions;
    backoffAttempts?: number;
    backoffMin?: number;
    backoffMax?: number;
}

export interface ClientExternalAccountBindingOptions {
    kid: string;
    hmacKey: string;
}

export interface ClientAutoOptions {
    csr: WebCsrBuffer | CsrString;
    challengeCreateFn: (
        authz: Authorization,
        challenge: rfc8555.Challenge,
        keyAuthorization: string
    ) => Promise<any>;
    challengeRemoveFn: (
        authz: Authorization,
        challenge: rfc8555.Challenge,
        keyAuthorization: string
    ) => Promise<any>;
    email?: string;
    termsOfServiceAgreed?: boolean;
    skipChallengeVerification?: boolean;
    challengePriority?: string[];
    preferredChain?: string;
}

export class Client {
    constructor(opts: ClientOptions);
    getTermsOfServiceUrl(): Promise<string>;
    getAccountUrl(): string;
    createAccount(
        data?: rfc8555.AccountCreateRequest
    ): Promise<rfc8555.Account>;
    updateAccount(
        data?: rfc8555.AccountUpdateRequest
    ): Promise<rfc8555.Account>;
    updateAccountKey(
        newAccountKey: LooseKeyPair,
        data?: object
    ): Promise<rfc8555.Account>;
    createOrder(data: rfc8555.OrderCreateRequest): Promise<Order>;
    getOrder(order: Pick<Order, "url">): Promise<Order>;
    finalizeOrder(order: Order, csr: WebCsrBuffer | CsrString): Promise<Order>;
    getAuthorizations(order: Order): Promise<Authorization[]>;
    deactivateAuthorization(authz: Authorization): Promise<Authorization>;
    getChallengeKeyAuthorization(challenge: rfc8555.Challenge): Promise<string>;
    verifyChallenge(
        authz: Authorization,
        challenge: rfc8555.Challenge
    ): Promise<boolean>;
    completeChallenge(challenge: rfc8555.Challenge): Promise<rfc8555.Challenge>;
    waitForValidStatus<T = Order | Authorization | rfc8555.Challenge>(
        item: T
    ): Promise<T>;
    getCertificate(order: Order, preferredChain?: string): Promise<string>;
    revokeCertificate(
        cert: WebCertificateBuffer | CertificateString,
        data?: rfc8555.CertificateRevocationRequest
    ): Promise<void>;
    auto(opts: ClientAutoOptions): Promise<string>;
}

/**
 * Directory URLs
 */

export const directory: {
    buypass: {
        staging: string;
        production: string;
    };
    google: {
        staging: string;
        production: string;
    };
    letsencrypt: {
        staging: string;
        production: string;
    };
    zerossl: {
        production: string;
    };
};

/**
 * Crypto
 */

export interface CertificateDomains {
    commonName: string;
    altNames: string[];
}

export interface CertificateIssuer {
    commonName: string;
}

export interface CertificateInfo {
    issuer: CertificateIssuer;
    domains: CertificateDomains;
    notAfter: Date;
    notBefore: Date;
}

export interface CsrOptions {
    keySize?: number;
    commonName?: string;
    altNames?: string[];
    country?: string;
    state?: string;
    locality?: string;
    organization?: string;
    organizationUnit?: string;
    emailAddress?: string;
}

export interface RsaPublicJwk {
    e: string;
    kty: string;
    n: string;
}

export interface EcdsaPublicJwk {
    crv: string;
    kty: string;
    x: string;
    y: string;
}

export interface KeyPair {
    privateKey: WebPrivateKeyBuffer;
    publicKey: WebPublicKeyBuffer;
}

export interface LooseKeyPair {
    privateKey: WebPrivateKeyBuffer | PrivateKeyString;
    publicKey: WebPublicKeyBuffer | PublicKeyString;
}

export interface WebCryptoInterface {
    createRsaKeyPair(modulusLength?: number): Promise<KeyPair>;
    createEcdsaKeyPair(namedCurve?: string): Promise<KeyPair>;
    getJwk(pem: Uint8Array | string): Promise<object>;
    getWebCryptoKeyPair(keyPair: {privateKey: string|Uint8Array, publicKey: string|Uint8Array}): Promise<[{privateKey: CryptoKey, publicKey: CryptoKey}, webcryptoType.RsaHashedImportParams | webcryptoType.EcdsaParams]>;
    splitPemChain(chainPem: Uint8Array | string): string[];
    getPemBodyAsB64u(pem: Uint8Array | string): string;
    readCsrDomains(csrPem: Uint8Array | string): CertificateDomains;
    readCertificateInfo(certPem: Uint8Array | string): CertificateInfo;
    createCsr(
        data: CsrOptions,
        keyPem?: LooseKeyPair | null
    ): Promise<[KeyPair, Uint8Array]>;
    createAlpnCertificate(
        authz: { identifier: { value: string } },
        keyAuthorization: string,
        keyPem?: LooseKeyPair | null
    ): Promise<[KeyPair, Uint8Array]>;
    isAlpnCertificateAuthorizationValid(
        certPem: Uint8Array | string,
        keyAuthorization: string
    ): Promise<boolean>;
}

export const webcrypto: WebCryptoInterface;

export interface CryptoInterface {
    createPrivateKey(keySize?: number): Promise<PrivateKeyBuffer>;
    createPrivateRsaKey(keySize?: number): Promise<PrivateKeyBuffer>;
    createPrivateEcdsaKey(
        namedCurve?: "P-256" | "P-384" | "P-521"
    ): Promise<PrivateKeyBuffer>;
    getPublicKey(
        keyPem:
            | PrivateKeyBuffer
            | PrivateKeyString
            | PublicKeyBuffer
            | PublicKeyString
    ): PublicKeyBuffer;
    getJwk(
        keyPem:
            | PrivateKeyBuffer
            | PrivateKeyString
            | PublicKeyBuffer
            | PublicKeyString
    ): RsaPublicJwk | EcdsaPublicJwk;
    splitPemChain(chainPem: CertificateBuffer | CertificateString): string[];
    getPemBodyAsB64u(pem: CertificateBuffer | CertificateString): string;
    readCsrDomains(csrPem: CsrBuffer | CsrString): CertificateDomains;
    readCertificateInfo(
        certPem: CertificateBuffer | CertificateString
    ): CertificateInfo;
    createCsr(
        data: CsrOptions,
        keyPem?: PrivateKeyBuffer | PrivateKeyString
    ): Promise<[PrivateKeyBuffer, CsrBuffer]>;
    createAlpnCertificate(
        authz: Authorization,
        keyAuthorization: string,
        keyPem?: PrivateKeyBuffer | PrivateKeyString
    ): Promise<[PrivateKeyBuffer, CertificateBuffer]>;
    isAlpnCertificateAuthorizationValid(
        certPem: CertificateBuffer | CertificateString,
        keyAuthorization: string
    ): boolean;
}

export const crypto: CryptoInterface;

/* TODO: LEGACY */
export interface CryptoLegacyInterface {
    createPrivateKey(size?: number): Promise<PrivateKeyBuffer>;
    createPublicKey(
        key: PrivateKeyBuffer | PrivateKeyString
    ): Promise<PublicKeyBuffer>;
    getPemBody(str: string): string;
    splitPemChain(str: string): string[];
    getModulus(
        input:
            | PrivateKeyBuffer
            | PrivateKeyString
            | PublicKeyBuffer
            | PublicKeyString
            | CertificateBuffer
            | CertificateString
            | CsrBuffer
            | CsrString
    ): Promise<Buffer>;
    getPublicExponent(
        input:
            | PrivateKeyBuffer
            | PrivateKeyString
            | PublicKeyBuffer
            | PublicKeyString
            | CertificateBuffer
            | CertificateString
            | CsrBuffer
            | CsrString
    ): Promise<Buffer>;
    readCsrDomains(csr: CsrBuffer | CsrString): Promise<CertificateDomains>;
    readCertificateInfo(
        cert: CertificateBuffer | CertificateString
    ): Promise<CertificateInfo>;
    createCsr(
        data: CsrOptions,
        key?: PrivateKeyBuffer | PrivateKeyString
    ): Promise<[PrivateKeyBuffer, CsrBuffer]>;
}

export const forge: CryptoLegacyInterface;

/**
 * Axios
 */

export const axios: XiorInstance;

/**
 * Logger
 */

export function setLogger(fn: (msg: string) => void): void;
