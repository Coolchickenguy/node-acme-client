/**
 * ACME HTTP client
 */

const x509 = require('@peculiar/x509');
const {
    getJwk, base64ToUint8Array, arrayBufferToBase64, base64ToBase64url,
} = require('./crypto/web');
const { log } = require('./logger');
const axios = require('./axios');

const textEncoder = new TextEncoder();

/**
 * ACME HTTP client
 *
 * @class
 * @param {string} directoryUrl ACME directory URL
 * @param {Uint8Array} accountKey PEM encoded account private key
 * @param {object} [opts.externalAccountBinding]
 * @param {string} [opts.externalAccountBinding.kid] External account binding KID
 * @param {string} [opts.externalAccountBinding.hmacKey] External account binding HMAC key
 */

class HttpClient {
    constructor(directoryUrl, accountKey, externalAccountBinding = {}) {
        this.directoryUrl = directoryUrl;
        this.accountKey = accountKey;
        this.externalAccountBinding = externalAccountBinding;

        this.maxBadNonceRetries = 5;
        this.jwk = null;

        this.directoryCache = null;
        this.directoryMaxAge = 86400;
        this.directoryTimestamp = 0;
    }

    /**
     * HTTP request
     *
     * @param {string} url HTTP URL
     * @param {string} method HTTP method
     * @param {object} [opts] Request options
     * @returns {Promise<object>} HTTP response
     */

    async request(url, method, opts = {}) {
        opts.url = url;
        opts.method = method;
        opts.validateStatus = null;

        /* Headers */
        if (typeof opts.headers === 'undefined') {
            opts.headers = {};
        }

        opts.headers['Content-Type'] = 'application/jose+json';

        /* Request */
        log(`HTTP request: ${method} ${url}`);
        const resp = await axios.request(opts);

        log(`RESP ${resp.status} ${method} ${url}`);

        // Remap headers
        const headers = {};
        for (const [key, value] of resp.headers) { // eslint-disable-line no-restricted-syntax
            headers[key] = value;
        }
        resp.headers = headers;

        return resp;
    }

    /**
     * Get ACME provider directory
     *
     * https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1
     *
     * @returns {Promise<object>} ACME directory contents
     */

    async getDirectory() {
        const now = Math.floor(Date.now() / 1000);
        const age = (now - this.directoryTimestamp);

        if (!this.directoryCache || (age > this.directoryMaxAge)) {
            log(`Refreshing ACME directory, age: ${age}`);
            const resp = await this.request(this.directoryUrl, 'get');

            if (resp.status >= 400) {
                throw new Error(`Attempting to read ACME directory returned error ${resp.status}: ${this.directoryUrl}`);
            }

            if (!resp.data) {
                throw new Error('Attempting to read ACME directory returned no data');
            }

            this.directoryCache = resp.data;
            this.directoryTimestamp = now;
        }

        return this.directoryCache;
    }

    /**
     * Get JSON Web Key
     *
     * @returns {Promise<object>} JSON Web Key
     */

    async getJwk() {
        if (!this.jwk) {
            this.jwk = await getJwk(this.accountKey);
        }

        return this.jwk;
    }

    /**
     * Get nonce from directory API endpoint
     *
     * https://datatracker.ietf.org/doc/html/rfc8555#section-7.2
     *
     * @returns {Promise<string>} Nonce
     */

    async getNonce() {
        const url = await this.getResourceUrl('newNonce');
        const resp = await this.request(url, 'head');

        if (!resp.headers['replay-nonce']) {
            throw new Error('Failed to get nonce from ACME provider');
        }

        return resp.headers['replay-nonce'];
    }

    /**
     * Get URL for a directory resource
     *
     * @param {string} resource API resource name
     * @returns {Promise<string>} URL
     */

    async getResourceUrl(resource) {
        const dir = await this.getDirectory();

        if (!dir[resource]) {
            throw new Error(`Unable to locate API resource URL in ACME directory: "${resource}"`);
        }

        return dir[resource];
    }

    /**
     * Get directory meta field
     *
     * @param {string} field Meta field name
     * @returns {Promise<string|null>} Meta field value
     */

    async getMetaField(field) {
        const dir = await this.getDirectory();

        if (('meta' in dir) && (field in dir.meta)) {
            return dir.meta[field];
        }

        return null;
    }

    /**
     * Prepare HTTP request body for signature
     *
     * @param {string} alg JWS algorithm
     * @param {string} url Request URL
     * @param {object} [payload] Request payload
     * @param {object} [opts]
     * @param {string} [opts.nonce] JWS anti-replay nonce
     * @param {string} [opts.kid] JWS KID
     * @returns {Promise<object>} Signed HTTP request body
     */

    async prepareSignedBody(alg, url, payload = null, { nonce = null, kid = null } = {}) {
        const header = { alg, url };

        /* Nonce */
        if (nonce) {
            log(`Using nonce: ${nonce}`);
            header.nonce = nonce;
        }

        /* KID or JWK */
        if (kid) {
            header.kid = kid;
        }
        else {
            header.jwk = await this.getJwk();
        }

        /* Body */
        return {
            payload: payload ? base64ToBase64url(arrayBufferToBase64(textEncoder.encode(JSON.stringify(payload)))) : '',
            protected: base64ToBase64url(arrayBufferToBase64(textEncoder.encode(JSON.stringify(header)))),
        };
    }

    /**
     * Create JWS HTTP request body using HMAC
     *
     * @param {string} hmacKey HMAC key
     * @param {string} url Request URL
     * @param {object} [payload] Request payload
     * @param {object} [opts]
     * @param {string} [opts.nonce] JWS anti-replay nonce
     * @param {string} [opts.kid] JWS KID
     * @returns {Promise<object>} Signed HMAC request body
     */

    async createSignedHmacBody(hmacKey, url, payload = null, { nonce = null, kid = null } = {}) {
        const result = await this.prepareSignedBody('HS256', url, payload, { nonce, kid });

        /* Signature */
        const signer = await crypto.subtle.importKey(
            'raw',
            base64ToUint8Array((hmacKey)),
            {
                name: 'HMAC',
                hash: { name: 'SHA-256' },
            },
            false, // Key can't be exported
            ['sign', 'verify'],
        );
        const data = new TextEncoder().encode(`${result.protected}.${result.payload}`);
        const signature = await crypto.subtle.sign('HMAC', signer, data);
        result.signature = base64ToBase64url(arrayBufferToBase64(signature));

        return result;
    }

    /**
     * Create JWS HTTP request body using RSA or ECC
     *
     * https://datatracker.ietf.org/doc/html/rfc7515
     *
     * @param {string} url Request URL
     * @param {object} [payload] Request payload
     * @param {object} [opts]
     * @param {string} [opts.nonce] JWS nonce
     * @param {string} [opts.kid] JWS KID
     * @returns {Promise<object>} JWS request body
     */

    async createSignedBody(url, payload = null, { nonce = null, kid = null } = {}) {
        const jwk = await this.getJwk();
        let headerAlg = 'RS256';
        let signerAlg = 'SHA256';

        /* https://datatracker.ietf.org/doc/html/rfc7518#section-3.1 */
        if (jwk.crv && (jwk.kty === 'EC')) {
            headerAlg = 'ES256';

            if (jwk.crv === 'P-384') {
                headerAlg = 'ES384';
                signerAlg = 'SHA384';
            }
            else if (jwk.crv === 'P-521') {
                headerAlg = 'ES512';
                signerAlg = 'SHA512';
            }
        }

        /* Prepare body and signer */
        const result = await this.prepareSignedBody(headerAlg, url, payload, { nonce, kid });
        const privateKeyDec = x509.PemConverter.decodeFirst(new TextDecoder().decode(this.accountKey));
        const privateKey = await crypto.subtle.importKey(
            'pkcs8',
            privateKeyDec,
            signerAlg,
            true,
            ['sign'],
        );
        const data = new TextEncoder().encode(`${result.protected}.${result.payload}`);
        const signature = await crypto.subtle.sign(
            {
                name: 'RSASSA-PKCS1-v1_5',
            },
            privateKey,
            data,
        );
        /* Signature - https://stackoverflow.com/questions/39554165 */
        result.signature = base64ToBase64url(arrayBufferToBase64(signature));

        return result;
    }

    /**
     * Signed HTTP request
     *
     * https://datatracker.ietf.org/doc/html/rfc8555#section-6.2
     *
     * @param {string} url Request URL
     * @param {object} payload Request payload
     * @param {object} [opts]
     * @param {string} [opts.kid] JWS KID
     * @param {string} [opts.nonce] JWS anti-replay nonce
     * @param {boolean} [opts.includeExternalAccountBinding] Include EAB in request
     * @param {number} [attempts] Request attempt counter
     * @returns {Promise<object>} HTTP response
     */

    async signedRequest(url, payload, { kid = null, nonce = null, includeExternalAccountBinding = false } = {}, attempts = 0) {
        if (!nonce) {
            nonce = await this.getNonce();
        }

        /* External account binding */
        if (includeExternalAccountBinding && this.externalAccountBinding) {
            if (this.externalAccountBinding.kid && this.externalAccountBinding.hmacKey) {
                const jwk = await this.getJwk();
                const eabKid = this.externalAccountBinding.kid;
                const eabHmacKey = this.externalAccountBinding.hmacKey;

                payload.externalAccountBinding = await this.createSignedHmacBody(eabHmacKey, url, jwk, { kid: eabKid });
            }
        }

        /* Sign body and send request */
        const data = await this.createSignedBody(url, payload, { nonce, kid });
        const resp = await this.request(url, 'post', { data });

        /* Retry on bad nonce - https://datatracker.ietf.org/doc/html/rfc8555#section-6.5 */
        if (resp.data && resp.data.type && (resp.status === 400) && (resp.data.type === 'urn:ietf:params:acme:error:badNonce') && (attempts < this.maxBadNonceRetries)) {
            nonce = resp.headers['replay-nonce'] || null;
            attempts += 1;

            log(`Caught invalid nonce error, retrying (${attempts}/${this.maxBadNonceRetries}) signed request to: ${url}`);
            return this.signedRequest(url, payload, { kid, nonce, includeExternalAccountBinding }, attempts);
        }

        /* Return response */
        return resp;
    }
}

/* Export client */
module.exports = HttpClient;
