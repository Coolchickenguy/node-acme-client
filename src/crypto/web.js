const net = require('net');
const x509 = require('@peculiar/x509');
const asn1js = require('asn1js');

const globalValue = typeof window === 'undefined' // eslint-disable-line no-nested-ternary
    ? typeof globalThis === 'undefined'
        ? global
        : globalThis // eslint-disable-line no-undef
    : window; // eslint-disable-line no-nested-ternary, no-undef
// Use web crypto if avalible

/**
 * @type {{"crypto":Crypto}}
 */
const { crypto } = globalValue;

if (crypto === undefined) {
    throw new Error('Web crypto is not avalible');
}
exports.crypto = crypto;
/* Use Node.js Web Crypto API */
x509.cryptoProvider.set(crypto);

/* id-ce-subjectAltName - https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6 */
const subjectAltNameOID = '2.5.29.17';

/* id-pe-acmeIdentifier - https://datatracker.ietf.org/doc/html/rfc8737#section-6.1 */
const alpnAcmeIdentifierOID = '1.3.6.1.5.5.7.1.31';

/* Utils */
const textDecoder = new TextDecoder('utf-8');
const textEncoder = new TextEncoder();

/**
 * Convert a base64 string to base64url
 * @param {str} base64String
 * @returns the base64url
 */
function base64ToBase64url(base64String) {
    return base64String
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
exports.base64ToBase64url = base64ToBase64url;

function formatAsPem(str) {
    return str.match(/.{1,64}/g).join('\n');
}

/**
 * Generate a random number safely with the web crypto api
 * @param {number} min The minimum number this function will return
 * @param {number} max The maximum number this function will return
 * @returns The random number
 */
function getSecureRandomInt(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    if (max <= min) throw new Error('Max must be greater than min.');

    const range = max - min + 1;
    const uint32 = new Uint32Array(1);
    const maxRange = Math.floor(0xffffffff / range) * range;

    let random;
    do {
        crypto.getRandomValues(uint32);
        [random] = uint32;
    } while (random >= maxRange); // avoid modulo bias

    return min + (random % range);
}

function arrayBufferToBase64(buffer) {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(binary);
}
exports.arrayBufferToBase64 = arrayBufferToBase64;

function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
exports.base64ToUint8Array = base64ToUint8Array;

async function exportKeyToPem(key, format, label) {
    const exported = await crypto.subtle.exportKey(format, key);
    const base64 = arrayBufferToBase64(exported);
    return `-----BEGIN ${label}-----\n${formatAsPem(
        base64,
    )}\n-----END ${label}-----`;
}

function areUint8ArraysEqual(a, b) {
    if (a.length !== b.length) return false;

    for (let i = 0; i < a.length; i += 1) {
        if (a[i] !== b[i]) return false;
    }

    return true;
}
/* api */

/**
 * Generate a RSA key pair
 *
 * @param {number} [modulusLength] Size of the keys modulus in bits, default: `2048`
 * @returns {Promise<{"privateKey":Uint8Array,"publicKey":Uint8Array}>} PEM encoder RSA key pair
 * @example Generate private RSA key
 *
 * ```js
 * const {publicKey, privateKey} = await acme.crypto.createRsaKeyPair();
 * ```
 *
 * @example Private RSA key with modulus size 4096
 * ```js
 * const {publicKey, privateKey} = await acme.crypto.createRsaKeyPair(4096);
 * ```
 */

async function createRsaKeyPair(modulusLength = 2048) {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
            hash: 'SHA-256',
        },
        true,
        ['sign', 'verify'],
    );

    const privateKey = textEncoder.encode(
        await exportKeyToPem(keyPair.privateKey, 'pkcs8', 'PRIVATE KEY'),
    );
    const publicKey = textEncoder.encode(
        await exportKeyToPem(keyPair.publicKey, 'spki', 'PUBLIC KEY'),
    );

    return { privateKey, publicKey };
}

exports.createRsaKeyPair = createRsaKeyPair;

/**
 * Generate a private ECDSA key
 *
 * @param {string} [namedCurve] ECDSA curve name (P-256, P-384 or P-521), default `P-256`
 * @returns {Promise<{"privateKey":Uint8Array,"publicKey":Uint8Array}>} PEM encoded ECDSA key pair
 *
 * @example Generate private ECDSA key
 * ```js
 * const {publicKey, privateKey} = await acme.webcrypto.createEcdsaKeyPair();
 * ```
 *
 * @example Private ECDSA key using P-384 curve
 * ```js
 * const {publicKey, privateKey} = await acme.webcrypto.createEcdsaKeyPair('P-384');
 * ```
 */

exports.createEcdsaKeyPair = async function createEcdsaKeyPair(
    namedCurve = 'P-256',
) {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve, // e.g., "P-256", "P-384", "P-521"
        },
        true, // extractable
        ['sign', 'verify'],
    );

    const privateKey = textEncoder.encode(
        await exportKeyToPem(keyPair.privateKey, 'pkcs8', 'PRIVATE KEY'),
    );
    const publicKey = textEncoder.encode(
        await exportKeyToPem(keyPair.publicKey, 'spki', 'PUBLIC KEY'),
    );

    return { privateKey, publicKey };
};

/**
 * Get a JSON Web Key derived from a RSA or ECDSA key
 *
 * https://datatracker.ietf.org/doc/html/rfc7517
 *
 * @param {Uint8Array|string} keyPem PEM encoded public key
 * @returns {object} JSON Web Key
 *
 * @example Get JWK
 * ```js
 * const jwk = acme.crypto.getJwk(privateKey);
 * ```
 */

async function getJwk(pem) {
    if (pem instanceof Uint8Array) {
        pem = textDecoder.decode(pem);
    }

    // Parse the public key
    const pub = new x509.PublicKey(pem);

    // Export as CryptoKey while letting the library infer algorithm and parameters
    const cryptoKey = await pub.export(undefined, ['verify']);

    // Export to JWK
    const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
    return jwk;
}

exports.getJwk = getJwk;

/**
 * Produce CryptoKeyPair and signing algorithm from a PEM encoded public and private key
 *
 * @param {{privateKey: string|Uint8Array, publicKey: string|Uint8Array}} keyPem PEM encoded public and private key
 * @returns {Promise<[{privateKey: CryptoKey, publicKey: CryptoKey}, RsaHashedImportParams | EcdsaParams]>} The key pair and the signature algorithm
 */

async function getWebCryptoKeyPair(keyPair) {
    const jwk = await getJwk(keyPair.publicKey);

    /* Signing algorithm */
    const sigalg = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
    };

    if (jwk.kty === 'EC') {
        sigalg.name = 'ECDSA';
        sigalg.namedCurve = jwk.crv;

        if (jwk.crv === 'P-384') {
            sigalg.hash.name = 'SHA-384';
        }

        if (jwk.crv === 'P-521') {
            sigalg.hash.name = 'SHA-512';
        }
    }

    /* Decode PEM and import into CryptoKeyPair */
    const privateKeyDec = x509.PemConverter.decodeFirst(textDecoder.decode(keyPair.privateKey));
    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyDec,
        sigalg,
        true,
        ['sign'],
    );
    const publicKey = await crypto.subtle.importKey('jwk', jwk, sigalg, true, [
        'verify',
    ]);

    return [{ privateKey, publicKey }, sigalg];
}

exports.getWebCryptoKeyPair = getWebCryptoKeyPair;

/**
 * Split chain of PEM encoded objects from string into array
 *
 * @param {Uint8Array|string} chainPem PEM encoded object chain
 * @returns {string[]} Array of PEM objects including headers
 */

function splitPemChain(chainPem) {
    if ((chainPem instanceof Uint8Array)) {
        chainPem = textDecoder.decode(chainPem);
    }

    /* Decode into array and re-encode */
    return x509.PemConverter.decodeWithHeaders(chainPem).map((params) => x509.PemConverter.encode([params]));
}

exports.splitPemChain = splitPemChain;

/**
 * Parse body of PEM encoded object and return a Base64URL string
 * If multiple objects are chained, the first body will be returned
 *
 * @param {Uint8Array|string} pem PEM encoded chain or object
 * @returns {string} Base64URL-encoded body
 */

exports.getPemBodyAsB64u = (pem) => {
    const chain = splitPemChain(pem);

    if (!chain.length) {
        throw new Error('Unable to parse PEM body from string');
    }

    /* Select first object, extract body and convert to b64u */
    const dec = x509.PemConverter.decodeFirst(chain[0]);
    return base64ToBase64url(arrayBufferToBase64(dec));
};

/**
 * Parse domains from a certificate or CSR
 *
 * @private
 * @param {object} input x509.Certificate or x509.Pkcs10CertificateRequest
 * @returns {object} {commonName, altNames}
 */

function parseDomains(input) {
    const commonName = input.subjectName.getField('CN').pop() || null;
    const altNamesRaw = input.getExtension(subjectAltNameOID);
    let altNames = [];

    if (altNamesRaw) {
        const altNamesExt = new x509.SubjectAlternativeNameExtension(
            altNamesRaw.rawData,
        );
        altNames = altNames.concat(altNamesExt.names.items.map((i) => i.value));
    }

    return {
        commonName,
        altNames,
    };
}

/**
 * Read domains from a Certificate Signing Request
 *
 * @param {Uint8Array|string} csrPem PEM encoded Certificate Signing Request
 * @returns {object} {commonName, altNames}
 *
 * @example Read Certificate Signing Request domains
 * ```js
 * const { commonName, altNames } = acme.crypto.readCsrDomains(certificateRequest);
 *
 * console.log(`Common name: ${commonName}`);
 * console.log(`Alt names: ${altNames.join(', ')}`);
 * ```
 */

exports.readCsrDomains = (csrPem) => {
    if ((csrPem instanceof Uint8Array)) {
        csrPem = textDecoder.decode(csrPem);
    }

    const dec = x509.PemConverter.decodeFirst(csrPem);
    const csr = new x509.Pkcs10CertificateRequest(dec);
    return parseDomains(csr);
};

/**
 * Read information from a certificate
 * If multiple certificates are chained, the first will be read
 *
 * @param {Uint8Array|string} certPem PEM encoded certificate or chain
 * @returns {object} Certificate info
 *
 * @example Read certificate information
 * ```js
 * const info = acme.crypto.readCertificateInfo(certificate);
 * const { commonName, altNames } = info.domains;
 *
 * console.log(`Not after: ${info.notAfter}`);
 * console.log(`Not before: ${info.notBefore}`);
 *
 * console.log(`Common name: ${commonName}`);
 * console.log(`Alt names: ${altNames.join(', ')}`);
 * ```
 */

exports.readCertificateInfo = (certPem) => {
    if ((certPem instanceof Uint8Array)) {
        certPem = textDecoder.decode(certPem);
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
 * Determine ASN.1 character string type for CSR subject field name
 *
 * https://datatracker.ietf.org/doc/html/rfc5280
 * https://github.com/PeculiarVentures/x509/blob/ecf78224fd594abbc2fa83c41565d79874f88e00/src/name.ts#L65-L71
 *
 * @private
 * @param {string} field CSR subject field name
 * @returns {string} ASN.1 character string type
 */

function getCsrAsn1CharStringType(field) {
    switch (field) {
        case 'C':
            return 'printableString';
        case 'E':
            return 'ia5String';
        default:
            return 'utf8String';
    }
}

/**
 * Create array of subject fields for a Certificate Signing Request
 *
 * https://github.com/PeculiarVentures/x509/blob/ecf78224fd594abbc2fa83c41565d79874f88e00/src/name.ts#L65-L71
 *
 * @private
 * @param {object} input Key-value of subject fields
 * @returns {object[]} Certificate Signing Request subject array
 */

function createCsrSubject(input) {
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
 *
 * https://github.com/PeculiarVentures/x509/blob/ecf78224fd594abbc2fa83c41565d79874f88e00/src/extensions/subject_alt_name.ts
 *
 * @private
 * @param {string[]} altNames Array of alt names
 * @returns {x509.SubjectAlternativeNameExtension} Subject alternate name extension
 */

function createSubjectAltNameExtension(altNames) {
    return new x509.SubjectAlternativeNameExtension(
        altNames.map((value) => {
            const type = net.isIP(value) ? 'ip' : 'dns';
            return { type, value };
        }),
    );
}

/**
 * Create a Certificate Signing Request
 *
 * @param {object} data
 * @param {number} [data.keySize] Size of newly created RSA private key modulus in bits, default: `2048`
 * @param {string} [data.commonName] FQDN of your server
 * @param {string[]} [data.altNames] SAN (Subject Alternative Names), default: `[]`
 * @param {string} [data.country] 2 letter country code
 * @param {string} [data.state] State or province
 * @param {string} [data.locality] City
 * @param {string} [data.organization] Organization name
 * @param {string} [data.organizationUnit] Organizational unit name
 * @param {string} [data.emailAddress] Email address
 * @param {{"privateKey":Uint8Array|string,"publicKey":Uint8Array|string}} [keyPem] PEM encoded CSR public and private key
 * @returns {Promise<buffer[]>} [privateKey, certificateSigningRequest]
 *
 * @example Create a Certificate Signing Request
 * ```js
 * const [certificateKey, certificateRequest] = await acme.webcrypto.createCsr({
 *     altNames: ['test.example.com'],
 * });
 * ```
 *
 * @example Certificate Signing Request with both common and alternative names
 * > *Warning*: Certificate subject common name has been [deprecated](https://letsencrypt.org/docs/glossary/#def-CN) and its use is [discouraged](https://cabforum.org/uploads/BRv1.2.3.pdf).
 * ```js
 * const [certificateKey, certificateRequest] = await acme.webcrypto.createCsr({
 *     keySize: 4096,
 *     commonName: 'test.example.com',
 *     altNames: ['foo.example.com', 'bar.example.com'],
 * });
 * ```
 *
 * @example Certificate Signing Request with additional information
 * ```js
 * const [certificateKey, certificateRequest] = await acme.webcrypto.createCsr({
 *     altNames: ['test.example.com'],
 *     country: 'US',
 *     state: 'California',
 *     locality: 'Los Angeles',
 *     organization: 'The Company Inc.',
 *     organizationUnit: 'IT Department',
 *     emailAddress: 'contact@example.com',
 * });
 * ```
 *
 * @example Certificate Signing Request with ECDSA private key
 * ```js
 * const certificateKey = await acme.crypto.createEcdsaKeyPair();
 *
 * const [, certificateRequest] = await acme.crypto.webcreateCsr({
 *     altNames: ['test.example.com'],
 * }, certificateKey);
 * ```
 */

exports.createCsr = async (
    data,
    keyPem = null,
) => {
    if (!keyPem) {
        keyPem = await createRsaKeyPair(data.keySize);
    }
    else {
        if (!(keyPem.privateKey instanceof Uint8Array)) {
            keyPem.privateKey = textEncoder.encode(keyPem.privateKey);
        }
        if (!(keyPem.publicKey instanceof Uint8Array)) {
            keyPem.publicKey = textEncoder.encode(keyPem.publicKey);
        }
    }

    if (typeof data.altNames === 'undefined') {
        data.altNames = [];
    }

    /* Ensure subject common name is present in SAN - https://cabforum.org/wp-content/uploads/BRv1.2.3.pdf */
    if (data.commonName && !data.altNames.includes(data.commonName)) {
        data.altNames.unshift(data.commonName);
    }
    /* CryptoKeyPair and signing algorithm from private key */
    const [keys, signingAlgorithm] = await getWebCryptoKeyPair(keyPem);

    const extensions = [
        /* https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3 */
        new x509.KeyUsagesExtension(
            x509.KeyUsageFlags.digitalSignature // eslint-disable-line no-bitwise
                | x509.KeyUsageFlags.keyEncipherment,
        ),

        /* https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6 */
        createSubjectAltNameExtension(data.altNames),
    ];

    /* Create CSR */
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        keys,
        extensions,
        signingAlgorithm,
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

    /* Done */
    const pem = csr.toString('pem');
    return [keyPem, textEncoder.encode(pem)];
};

/**
 * Create a self-signed ALPN certificate for TLS-ALPN-01 challenges
 *
 * https://datatracker.ietf.org/doc/html/rfc8737
 *
 * @param {object} authz Identifier authorization
 * @param {string} keyAuthorization Challenge key authorization
 * @param {{"privateKey":Uint8Array|string,"publicKey":Uint8Array|string}} [keyPem] PEM encoded CSR public and private key
 * @returns {Promise<Uint8Array[]>} [privateKey, certificate]
 *
 * @example Create a ALPN certificate
 * ```js
 * const [alpnKey, alpnCertificate] = await acme.webcrypto.createAlpnCertificate(authz, keyAuthorization);
 * ```
 *
 * @example Create a ALPN certificate with ECDSA private key
 * ```js
 * const alpnKey = await acme.webcrypto.createEcdsaKeyPair();
 * const [, alpnCertificate] = await acme.webcrypto.createAlpnCertificate(authz, keyAuthorization, alpnKey);
 * ```
 */

exports.createAlpnCertificate = async (
    authz,
    keyAuthorization,
    keyPem = null,
) => {
    if (!keyPem) {
        keyPem = await createRsaKeyPair();
    }
    else {
        if (!(keyPem.privateKey instanceof Uint8Array)) {
            keyPem.privateKey = textEncoder.encode(keyPem.privateKey);
        }
        if (!(keyPem.publicKey instanceof Uint8Array)) {
            keyPem.publicKey = textEncoder.encode(keyPem.publicKey);
        }
    }

    const now = new Date();
    const commonName = authz.identifier.value;

    /* Pseudo-random serial - max 20 bytes, 11 for epoch (year 5138), 9 random */
    const random = getSecureRandomInt(1, 999999999);
    const serialNumber = `${Math.floor(now.getTime() / 1000)}${random}`;

    /* CryptoKeyPair and signing algorithm from private key */
    const [keys, signingAlgorithm] = await getWebCryptoKeyPair(keyPem);

    const extensions = [
        /* https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3 */
        new x509.KeyUsagesExtension(
            x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, // eslint-disable-line no-bitwise
            true,
        ),

        /* https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9 */
        new x509.BasicConstraintsExtension(true, 2, true),

        /* https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2 */
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),

        /* https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6 */
        createSubjectAltNameExtension([commonName]),
    ];

    /* ALPN extension */
    const payload = await crypto.subtle.digest(
        'SHA-256',
        textEncoder.encode(keyAuthorization),
    );
    const octstr = new asn1js.OctetString({ valueHex: new Uint8Array(payload) });
    extensions.push(
        new x509.Extension(alpnAcmeIdentifierOID, true, octstr.toBER()),
    );

    /* Self-signed ALPN certificate */
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        keys,
        signingAlgorithm,
        extensions,
        serialNumber,
        notBefore: now,
        notAfter: now,
        name: createCsrSubject({
            CN: commonName,
        }),
    });

    /* Done */
    const pem = cert.toString('pem');
    return [keyPem, textEncoder.encode(pem)];
};

/**
 * Validate that a ALPN certificate contains the expected key authorization
 *
 * @param {Uint8Array|string} certPem PEM encoded certificate
 * @param {string} keyAuthorization Expected challenge key authorization
 * @returns {Promise<boolean>} True when valid
 */

exports.isAlpnCertificateAuthorizationValid = async (
    certPem,
    keyAuthorization,
) => {
    const expected = await crypto.subtle.digest(
        'SHA-256',
        textEncoder.encode(keyAuthorization),
    );

    /* Attempt to locate ALPN extension */
    const cert = new x509.X509Certificate(certPem);
    const ext = cert.getExtension(alpnAcmeIdentifierOID);

    if (!ext) {
        throw new Error(
            'Unable to locate ALPN extension within parsed certificate',
        );
    }

    /* Decode extension value */
    const parsed = asn1js.fromBER(ext.value);
    const result = new Uint8Array(parsed.result.valueBlock.valueHexView);

    /* Return true if match */
    return areUint8ArraysEqual(
        result,
        new Uint8Array(expected),
    );
};
