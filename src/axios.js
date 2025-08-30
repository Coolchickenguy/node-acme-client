/**
 * Xior instance with retry, error handling, and custom headers
 */

const xior = require('xior');
const { parseRetryAfterHeader } = require('./util');
const { log } = require('./logger');
const pkg = require('./../package.json');

/**
 * Minimal AxiosError replacement
 */
class HttpError extends Error {
    constructor(message, code, config, request, response) {
        super(message);
        this.name = 'HttpError';
        this.code = code;
        this.config = config;
        this.request = request;
        this.response = response;
        this.isHttpError = true;
    }
}

/**
 * Create instance
 */
const instance = xior.default.create();

/* Default User-Agent */
instance.defaults.headers = {
    ...(instance.defaults.headers || {}),
    'User-Agent': `node-${pkg.name}/${pkg.version}`,
};

/* Default ACME settings */
instance.defaults.acmeSettings = {
    httpChallengePort: 80,
    httpsChallengePort: 443,
    tlsAlpnChallengePort: 443,

    retryMaxAttempts: 5,
    retryDefaultDelay: 5,
};

/**
 * Retryable error checker
 */
function isRetryableError(error) {
    return (
        error.code !== 'ECONNABORTED'
        && error.code !== 'ERR_NOCK_NO_MATCH'
        && (!error.response
            || error.response.status === 429
            || (error.response.status >= 500 && error.response.status <= 599))
    );
}

/**
 * Status validator (throws custom HttpError if needed)
 */
function validateStatus(response) {
    const validator = response.config.retryValidateStatus;

    if (!response.status || !validator || validator(response.status)) {
        return response;
    }

    const code = Math.floor(response.status / 100) === 4
        ? 'ERR_BAD_REQUEST'
        : 'ERR_BAD_RESPONSE';

    throw new HttpError(
        `Request failed with status code ${response.status}`,
        code,
        response.config,
        response.request,
        response,
    );
}

/**
 * Intercept requests to override status validation
 */
instance.interceptors.request.use((config) => {
    if (!('retryValidateStatus' in config)) {
        config.retryValidateStatus = config.validateStatus;
    }

    // Prevent xior from auto-throwing on status
    config.validateStatus = () => false;
    return config;
});

/**
 * Intercept responses for retry logic
 */
instance.interceptors.response.use(null, async (error) => {
    const { config, response } = error;

    if (!config) {
        return Promise.reject(error);
    }

    /* Pick up errors we want to retry */
    if (isRetryableError(error)) {
        const { retryMaxAttempts, retryDefaultDelay } = instance.defaults.acmeSettings;
        config.retryAttempt = ('retryAttempt' in config) ? (config.retryAttempt + 1) : 1;

        if (config.retryAttempt <= retryMaxAttempts) {
            const code = response ? `HTTP ${response.status}` : error.code;
            log(`Caught ${code}, retry attempt ${config.retryAttempt}/${retryMaxAttempts} to URL ${config.url}`);

            /* Attempt to parse Retry-After header, fallback to default delay */
            let retryAfter = response ? parseRetryAfterHeader(response.headers['retry-after']) : 0;

            if (retryAfter > 0) {
                log(`Found retry-after response header with value: ${response.headers['retry-after']}, waiting ${retryAfter} seconds`);
            }
            else {
                retryAfter = (retryDefaultDelay * config.retryAttempt);
                log(`Unable to locate or parse retry-after response header, waiting ${retryAfter} seconds`);
            }

            /* Wait and retry the request */
            await new Promise((resolve) => { setTimeout(resolve, (retryAfter * 1000)); });
            return instance.request(config);
        }
    }

    /* Validate and return response */
    return validateStatus(response);
});

/**
 * Export configured instance
 */
module.exports = instance;
