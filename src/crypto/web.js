/**
 * Web Crypto API-based crypto interface
 *
 * This module provides a similar API to src/crypto/index.js,
 * but uses only the Web Crypto API and JWK/CryptoKey objects.
 */

const net = require('net');
const x509 = require('@peculiar/x509');
const asn1js = require('asn1js');

const globalValue = typeof window === 'undefined' // eslint-disable-line no-nested-ternary
    ? typeof globalThis === 'undefined'
        ? global
        : globalThis // eslint-disable-line no-undef
    : window; // eslint-disable-line no-nested-ternary, no-undef
// Use web crypto if avalible, fall back to @peculiar/webcrypto if in nodejs and it is not
/**
 * @type {Crypto}
 */
const crypto = globalValue.crypto === null || globalValue.crypto === undefined // eslint-disable-line no-nested-ternary
    ? typeof window === 'undefined'
        ? new (require('@peculiar/webcrypto').Crypto)() // eslint-disable-line global-require
        : null
    : globalValue.crypto;

/* Use Node.js Web Crypto API */
x509.cryptoProvider.set(crypto);

/* id-ce-subjectAltName - https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6 */
const subjectAltNameOID = '2.5.29.17';

/**
 * Generate a private RSA key (returns CryptoKeyPair)
 * @param {number} [modulusLength=2048]
 * @returns {Promise<CryptoKeyPair>}
 */
exports.createPrivateRsaKey = (modulusLength = 2048) => crypto.subtle.generateKey(
    {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
);

/**
 * Alias of createPrivateRsaKey
 */
exports.createPrivateKey = exports.createPrivateRsaKey;

/**
 * Generate a private ECDSA key (returns CryptoKeyPair)
 * @param {string} [namedCurve='P-256']
 * @returns {Promise<CryptoKeyPair>}
 */
exports.createPrivateEcdsaKey = (namedCurve = 'P-256') => crypto.subtle.generateKey(
    {
        name: 'ECDSA',
        namedCurve,
    },
    true,
    ['sign', 'verify'],
);

/**
 * Export a public key from a CryptoKeyPair as JWK
 * @param {CryptoKey|CryptoKeyPair} key
 * @returns {Promise<object>} JWK
 */
exports.getPublicKey = (key) => {
    const publicKey = key.publicKey || key;
    return crypto.subtle.exportKey('jwk', publicKey);
};

/**
 * Export a public key as JWK (alias)
 * @param {CryptoKey|CryptoKeyPair} key
 * @returns {Promise<object>} JWK
 */
exports.getJwk = exports.getPublicKey;

/**
 * Import a private key from JWK
 * @param {object} jwk
 * @param {string} alg 'RSASSA-PKCS1-v1_5' or 'ECDSA'
 * @returns {Promise<CryptoKey>}
 */
exports.importPrivateKey = (jwk, alg = 'RSASSA-PKCS1-v1_5') => crypto.subtle.importKey(
    'jwk',
    jwk,
    alg === 'ECDSA'
        ? { name: 'ECDSA', namedCurve: jwk.crv }
        : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['sign'],
);

/**
 * Import a public key from JWK
 * @param {object} jwk
 * @param {string} alg 'RSASSA-PKCS1-v1_5' or 'ECDSA'
 * @returns {Promise<CryptoKey>}
 */
exports.importPublicKey = (jwk, alg = 'RSASSA-PKCS1-v1_5') => crypto.subtle.importKey(
    'jwk',
    jwk,
    alg === 'ECDSA'
        ? { name: 'ECDSA', namedCurve: jwk.crv }
        : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify'],
);

/**
 * Split chain of PEM encoded objects from string into array
 * @param {buffer|string} chainPem
 * @returns {string[]}
 */
exports.splitPemChain = (chainPem) => {
    if (Buffer.isBuffer(chainPem)) {
        chainPem = chainPem.toString();
    }
    return x509.PemConverter.decodeWithHeaders(chainPem)
        .map((params) => x509.PemConverter.encode([params]));
};

/**
 * Parse body of PEM encoded object and return a Base64URL string
 * If multiple objects are chained, the first body will be returned
 * @param {buffer|string} pem
 * @returns {string}
 */
exports.getPemBodyAsB64u = (pem) => {
    const chain = exports.splitPemChain(pem);
    if (!chain.length) {
        throw new Error('Unable to parse PEM body from string');
    }
    const dec = x509.PemConverter.decodeFirst(chain[0]);
    return Buffer.from(dec).toString('base64url');
};

/**
 * Parse domains from a certificate or CSR
 * @private
 * @param {object} input x509.Certificate or x509.Pkcs10CertificateRequest
 * @returns {object} {commonName, altNames}
 */
function parseDomains(input) {
    const commonName = input.subjectName.getField('CN').pop() || null;
    const altNamesRaw = input.getExtension(subjectAltNameOID);
    let altNames = [];
    if (altNamesRaw) {
        const altNamesExt = new x509.SubjectAlternativeNameExtension(altNamesRaw.rawData);
        altNames = altNames.concat(altNamesExt.names.items.map((i) => i.value));
    }
    return { commonName, altNames };
}

/**
 * Read domains from a Certificate Signing Request
 * @param {buffer|string} csrPem
 * @returns {object} {commonName, altNames}
 */
exports.readCsrDomains = (csrPem) => {
    if (Buffer.isBuffer(csrPem)) {
        csrPem = csrPem.toString();
    }
    const dec = x509.PemConverter.decodeFirst(csrPem);
    const csr = new x509.Pkcs10CertificateRequest(dec);
    return parseDomains(csr);
};

/**
 * Read information from a certificate
 * If multiple certificates are chained, the first will be read
 * @param {buffer|string} certPem
 * @returns {object}
 */
exports.readCertificateInfo = (certPem) => {
    if (Buffer.isBuffer(certPem)) {
        certPem = certPem.toString();
    }
    const dec = x509.PemConverter.decodeFirst(certPem);
    const cert = new x509.X509Certificate(dec);
    return {
        issuer: {
            commonName: cert.issuerName.getField('CN').pop() || null,
        },
        domains: parseDomains(cert),
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
    };
};

/**
 * Create array of subject fields for a Certificate Signing Request
 * @private
 * @param {object} input
 * @returns {object[]}
 */
function createCsrSubject(input) {
    function getCsrAsn1CharStringType(field) {
        switch (field) {
            case 'C': return 'printableString';
            case 'E': return 'ia5String';
            default: return 'utf8String';
        }
    }
    return Object.entries(input).reduce((result, [type, value]) => {
        if (value) {
            const ds = getCsrAsn1CharStringType(type);
            result.push({ [type]: [{ [ds]: value }] });
        }
        return result;
    }, []);
}

/**
 * Create x509 subject alternate name extension
 * @private
 * @param {string[]} altNames
 * @returns {x509.SubjectAlternativeNameExtension}
 */
function createSubjectAltNameExtension(altNames) {
    return new x509.SubjectAlternativeNameExtension(altNames.map((value) => {
        const type = net.isIP(value) ? 'ip' : 'dns';
        return { type, value };
    }));
}

/**
 * Create a Certificate Signing Request
 * @param {object} data
 * @param {CryptoKeyPair} [keyPair]
 * @returns {Promise<[CryptoKeyPair, Buffer]>}
 */
exports.createCsr = async (data, keyPair = null) => {
    if (!keyPair) {
        keyPair = await exports.createPrivateRsaKey(data.keySize);
    }
    if (typeof data.altNames === 'undefined') {
        data.altNames = [];
    }
    if (data.commonName && !data.altNames.includes(data.commonName)) {
        data.altNames.unshift(data.commonName);
    }
    const extensions = [
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment), // eslint-disable-line no-bitwise
        createSubjectAltNameExtension(data.altNames),
    ];
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        keys: keyPair,
        extensions,
        signingAlgorithm: keyPair.privateKey.algorithm,
        name: createCsrSubject({
            CN: data.commonName,
            C: data.country,
            ST: data.state,
            L: data.locality,
            O: data.organization,
            OU: data.organizationUnit,
            E: data.emailAddress,
        }),
    });
    const pem = csr.toString('pem');
    return [keyPair, Buffer.from(pem)];
};

exports.isAlpnCertificateAuthorizationValid = async (certPem, keyAuthorization) => {
    // Compute SHA-256 hash using Web Crypto
    const encoder = new TextEncoder();
    const data = encoder.encode(keyAuthorization);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const expected = Buffer.from(hashBuffer).toString('hex');

    // Parse certificate and extract ALPN extension (still need @peculiar/x509 and asn1js)
    const cert = new x509.X509Certificate(certPem);
    const ext = cert.getExtension('1.3.6.1.5.5.7.1.31');
    if (!ext) throw new Error('Unable to locate ALPN extension within parsed certificate');

    const parsed = asn1js.fromBER(ext.value);
    const result = Buffer.from(parsed.result.valueBlock.valueHexView).toString('hex');

    return result === expected;
};
