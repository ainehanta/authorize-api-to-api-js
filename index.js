require('dotenv').config()

const port = process.env.PORT || 3000

const storage = { token: undefined }

const { Issuer, generators } = require('openid-client')

const express = require('express')
const app = express()
const cookieParser = require('cookie-parser')

const CODE_VERIFIER_COOKIE_KEY = 'tacotsubo_auth_code_verifier'
const STATE_COOKIE_KEY = 'tacotsubo_auth_state'

let _auth0Issuer
let _auth0Client

async function getAuth0Issuer() {
    if(!_auth0Issuer) {
        _auth0Issuer = await Issuer.discover(process.env.AUTH0_DOMAIN)
        _auth0Issuer.end_session_endpoint = `${process.env.AUTH0_DOMAIN}/v2/logout`
        console.log(_auth0Issuer)
    }

    return _auth0Issuer
}

async function getAuth0Client() {
    if(!_auth0Client) {
        const auth0Issuer = await getAuth0Issuer()
        _auth0Client =  new auth0Issuer.Client({
            client_id: process.env.AUTH0_CLIENT_ID,
            client_secret: process.env.AUTH0_CLIENT_SECRET,
            redirect_uris: ['http://localhost:3000/callback'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_post',
        })
        console.log(_auth0Client)
    }

    return _auth0Client
}

app.use(cookieParser())

app.get('/', async (req, res, next) => {
    try {
        res.json(storage)
    } catch(error) {
        next(error)
    }
})

app.get('/connect', async (req, res, next) => {
    try {
        const auth0Client = await getAuth0Client()
        const codeVerifier = generators.codeVerifier()
        const codeChallenge = generators.codeChallenge(codeVerifier)

        const state = generators.state()

        const authorizationUrl = auth0Client.authorizationUrl({
            scope: `openid ${process.env.AUTH0_SCOPE}`,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            state,
            audience: process.env.AUTH0_AUDIENCE
        })
        console.log(authorizationUrl)

        res.cookie(CODE_VERIFIER_COOKIE_KEY, codeVerifier, {
            httpOnly: true
        })
        res.cookie(STATE_COOKIE_KEY, state, {
            httpOnly: true
        })
        res.redirect(authorizationUrl)
    } catch(error) {
        next(error)
    }
})

app.get('/disconnect', async (req, res, next) => {
    try {
        const auth0Client = await getAuth0Client()
        const logoutUrl = auth0Client.endSessionUrl({})
        storage.token = undefined
        res.redirect(logoutUrl)
    } catch(error) {
        next(error)
    }
})

app.get('/callback', async (req, res, next) => {
    try {
        const codeVerifier = req.cookies[CODE_VERIFIER_COOKIE_KEY]
        if (!codeVerifier) {
            throw new Error('Undefined Code Verifier')
        }
        console.log(codeVerifier)

        const state = req.cookies[STATE_COOKIE_KEY]
        if (!state) {
            throw new Error('Undefined State')
        }
        console.log(state)

        const auth0Client = await getAuth0Client()

        const params = auth0Client.callbackParams(req)
        console.log(params)

        const token = await auth0Client.oauthCallback(auth0Client.redirect_uris[0], params, {
            code_verifier: codeVerifier,
            state
        })
        console.log(token)

        storage.token = token

        res.json(token)
    } catch(error) {
        next(error)
    }
})

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})