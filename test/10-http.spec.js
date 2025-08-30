/**
 * HTTP client tests with undici MockAgent
 */

const { randomUUID: uuid } = require('crypto');
const { assert } = require('chai');
const { MockAgent, setGlobalDispatcher, getGlobalDispatcher } = require('undici');
const axios = require('../src/axios');
const HttpClient = require('../src/http');
const pkg = require('../package.json');

describe('http', () => {
    /**
     * @type {HttpClient}
     */
    let testClient;
    /**
     * @type {MockAgent}
     */
    let mockAgent;
    /**
     * @type {import("undici").Interceptable}
     */
    let mockPool;
    let originalDispatcher;

    const endpoint = `http://${uuid()}.example.com`;
    const defaultUserAgent = `node-${pkg.name}/${pkg.version}`;
    const customUserAgent = 'custom-ua-123';

    before(() => {
        originalDispatcher = getGlobalDispatcher();
        // Setup global dispatcher with undici MockAgent
        mockAgent = new MockAgent();
        mockAgent.disableNetConnect(); // Disable real HTTP requests
        setGlobalDispatcher(mockAgent);
    });

    beforeEach(() => {
        // Get a mock pool for the dynamic endpoint host
        mockPool = mockAgent.get(endpoint);
        testClient = new HttpClient();
    });

    afterEach(() => {
        mockPool.cleanMocks();
    });

    after(() => {
        mockAgent.close();
        setGlobalDispatcher(originalDispatcher);
    });

    /**
     * Initialize
     */
    it('should initialize clients', () => {
        assert.instanceOf(testClient, HttpClient);
    });

    /**
     * HTTP verbs
     */
    it('should http get', async () => {
        mockPool.intercept({ path: '/', method: 'GET' }).reply(200, 'ok');

        const resp = await testClient.request(endpoint, 'get');

        assert.isObject(resp);
        assert.strictEqual(resp.status, 200);
        assert.strictEqual(resp.data, 'ok');
    });

    it('should request using default user-agent', async () => {
        mockPool.intercept({
            path: '/',
            method: 'GET',
            headers: {
                'user-agent': defaultUserAgent,
            },
        }).reply(200, 'ok');

        const resp = await testClient.request(endpoint, 'get');

        assert.isObject(resp);
        assert.strictEqual(resp.status, 200);
        assert.strictEqual(resp.data, 'ok');
    });

    it('should reject using custom user-agent', async () => {
        mockPool.intercept({
            path: '/',
            method: 'GET',
            headers: {
                'user-agent': defaultUserAgent,
            },
        }).reply(200, 'ok');

        axios.defaults.headers = {
            ...(axios.defaults.headers || {}),
            'User-Agent': customUserAgent,
        };
        await assert.isRejected(testClient.request(endpoint, 'get'));
    });

    it('should request using custom user-agent', async () => {
        mockPool.intercept({
            path: '/',
            method: 'GET',
            headers: {
                'user-agent': customUserAgent,
            },
        }).reply(200, 'ok');

        axios.defaults.headers = {
            ...(axios.defaults.headers || {}),
            'User-Agent': customUserAgent,
        };

        const resp = await testClient.request(endpoint, 'get');

        assert.isObject(resp);
        assert.strictEqual(resp.status, 200);
        assert.strictEqual(resp.data, 'ok');
    });

    it('should reject using default user-agent', async () => {
        mockPool.intercept({
            path: '/',
            method: 'GET',
            headers: {
                'user-agent': customUserAgent,
            },
        }).reply(200, 'ok');

        axios.defaults.headers = {
            ...(axios.defaults.headers || {}),
            'User-Agent': defaultUserAgent,
        };

        await assert.isRejected(testClient.request(endpoint, 'get'));
    });

    /**
     * Retry on HTTP errors
     */

    it('should retry on 429 rate limit', async () => {
        let rateLimitCount = 0;

        mockPool.intercept({ path: '/', method: 'GET' }).reply(() => {
            rateLimitCount += 1;

            if (rateLimitCount < 3) {
                return {
                    statusCode: 429,
                    headers: {
                        'Retry-After': '1',
                    },
                    data: 'Rate Limit Exceeded',
                };
            }

            return { statusCode: 200, data: 'ok' };
        }).persist();

        assert.strictEqual(rateLimitCount, 0);

        const resp = await testClient.request(endpoint, 'get');

        assert.isObject(resp);
        assert.strictEqual(resp.status, 200);
        assert.strictEqual(resp.data, 'ok');
        assert.strictEqual(rateLimitCount, 3);
    });

    it('should retry on 5xx server error', async () => {
        let serverErrorCount = 0;

        // To limit retries, simulate fixed number of responses
        mockPool.intercept({ path: '/', method: 'GET' }).reply(() => {
            serverErrorCount += 1;
            return { statusCode: 500, data: 'Internal Server Error', headers: { 'Retry-After': '1' } };
        }).persist();

        assert.strictEqual(serverErrorCount, 0);

        const resp = await testClient.request(endpoint, 'get');

        assert.isObject(resp);
        assert.strictEqual(resp.status, 500);
        assert.strictEqual(serverErrorCount, 4); // Depends on your retry logic in HttpClient
    });
});
