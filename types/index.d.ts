/**
 * acme-client type definitions
 */

import { XiorInstance } from "xior";
import type { webcrypto } from "crypto";
import * as rfc8555 from "./rfc8555";

type CryptoKey = webcrypto.CryptoKey;
type CryptoKeyPair = webcrypto.CryptoKeyPair;

export type PrivateKeyBuffer = Buffer;
export type PublicKeyBuffer = Buffer;
export type CertificateBuffer = Buffer;
export type CsrBuffer = Buffer;

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
    accountKey: PrivateKeyBuffer | PrivateKeyString;
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
    csr: CsrBuffer | CsrString;
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
        newAccountKey: PrivateKeyBuffer | PrivateKeyString,
        data?: object
    ): Promise<rfc8555.Account>;
    createOrder(data: rfc8555.OrderCreateRequest): Promise<Order>;
    getOrder(order: Pick<Order, "url">): Promise<Order>;
    finalizeOrder(order: Order, csr: CsrBuffer | CsrString): Promise<Order>;
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
        cert: CertificateBuffer | CertificateString,
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

export interface WebCryptoInterface {
    /**
     * Generate a private RSA key (returns CryptoKeyPair)
     * @param modulusLength Size of the key modulus in bits, default: 2048
     */
    createPrivateRsaKey(modulusLength?: number): Promise<CryptoKeyPair>;

    /**
     * Alias of createPrivateRsaKey
     */
    createPrivateKey: WebCryptoInterface["createPrivateRsaKey"];

    /**
     * Generate a private ECDSA key (returns CryptoKeyPair)
     * @param namedCurve ECDSA curve name (P-256, P-384, or P-521), default: P-256
     */
    createPrivateEcdsaKey(namedCurve?: string): Promise<CryptoKeyPair>;

    /**
     * Export a public key from a CryptoKeyPair as JWK
     * @param key CryptoKey or CryptoKeyPair
     */
    getPublicKey(key: CryptoKey | CryptoKeyPair): Promise<object>;

    /**
     * Export a public key as JWK (alias)
     * @param key CryptoKey or CryptoKeyPair
     */
    getJwk: WebCryptoInterface["getPublicKey"];

    /**
     * Import a private key from JWK
     * @param jwk JWK object
     * @param alg Algorithm name ('RSASSA-PKCS1-v1_5' or 'ECDSA')
     */
    importPrivateKey(jwk: object, alg?: string): Promise<CryptoKey>;

    /**
     * Import a public key from JWK
     * @param jwk JWK object
     * @param alg Algorithm name ('RSASSA-PKCS1-v1_5' or 'ECDSA')
     */
    importPublicKey(jwk: object, alg?: string): Promise<CryptoKey>;

    /**
     * Split chain of PEM encoded objects from string into array
     * @param chainPem PEM encoded object chain
     */
    splitPemChain(chainPem: Buffer | string): string[];

    /**
     * Parse body of PEM encoded object and return a Base64URL string
     * If multiple objects are chained, the first body will be returned
     * @param pem PEM encoded chain or object
     */
    getPemBodyAsB64u(pem: Buffer | string): string;

    /**
     * Read domains from a Certificate Signing Request
     * @param csrPem PEM encoded Certificate Signing Request
     */
    readCsrDomains(csrPem: Buffer | string): {
        commonName: string | null;
        altNames: string[];
    };

    /**
     * Read information from a certificate
     * If multiple certificates are chained, the first will be read
     * @param certPem PEM encoded certificate or chain
     */
    readCertificateInfo(certPem: Buffer | string): {
        issuer: { commonName: string | null };
        domains: { commonName: string | null; altNames: string[] };
        notBefore: Date;
        notAfter: Date;
    };

    /**
     * Create a Certificate Signing Request
     * @param data Subject and extension data
     * @param keyPair Optional CryptoKeyPair to use
     */
    createCsr(
        data: {
            commonName: string;
            country?: string;
            state?: string;
            locality?: string;
            organization?: string;
            organizationUnit?: string;
            emailAddress?: string;
            altNames?: string[];
            keySize?: number;
        },
        keyPair?: CryptoKeyPair
    ): Promise<[CryptoKeyPair, Buffer]>;
}
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
