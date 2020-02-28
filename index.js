import cookie from 'cookie'

const auth0 = {
  domain: AUTH0_DOMAIN,
  clientId: AUTH0_CLIENT_ID,
  clientSecret: AUTH0_CLIENT_SECRET,
  callbackUrl: AUTH0_CALLBACK_URL,
}

const cookieKey = 'AUTH0-AUTH'

const exchangeCode = async code => {
  const body = JSON.stringify({
    grant_type: 'authorization_code',
    client_id: auth0.clientId,
    client_secret: auth0.clientSecret,
    code,
    redirect_uri: auth0.callbackUrl,
  })

  return setCookie(
    await fetch(AUTH0_DOMAIN + '/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    }),
  )
}

const setCookie = async exchange => {
  const body = await exchange.json()

  if (body.error) {
    throw new Error(body.error)
  }

  const date = new Date()
  date.setDate(date.getDate() + 1)

  const hashedBody = JSON.stringify(body) // TODO

  const headers = {
    Location: '/',
    'Set-cookie': `${cookieKey}=${hashedBody}; HttpOnly; SameSite=Lax; Expires=${date.toUTCString()}`,
  }

  return { headers, status: 302 }
}

const redirectUrl = `${auth0.domain}/authorize?audience=hasura&response_type=code&client_id=${auth0.clientId}&redirect_uri=${auth0.callbackUrl}&scope=openid%20profile%20email`

const handleRedirect = async event => {
  const url = new URL(event.request.url)
  const code = url.searchParams.get('code')
  if (code) {
    return exchangeCode(code)
  }
  return {}
}

const verify = event => {
  // https://github.com/pose/webcrypto-jwt/blob/master/index.js
  const decodeJWT = function(token) {
    var output = token
      .split('.')[1]
      .replace(/-/g, '+')
      .replace(/_/g, '/')
    switch (output.length % 4) {
      case 0:
        break
      case 2:
        output += '=='
        break
      case 3:
        output += '='
        break
      default:
        throw 'Illegal base64url string!'
    }

    // TODO Use shim or document incomplete browsers
    var result = atob(output)

    try {
      return decodeURIComponent(escape(result))
    } catch (err) {
      console.log(err)
      return result
    }
  }

  const cookieHeader = event.request.headers.get('Cookie')
  if (cookieHeader && cookieHeader.includes(cookieKey)) {
    const cookies = cookie.parse(cookieHeader)
    const { access_token } = JSON.parse(cookies[cookieKey])
    const { sub } = JSON.parse(decodeJWT(access_token))
    return { access_token, sub }
  }
  return {}
}

const authorize = event => {
  const authorization = verify(event)
  if (authorization.access_token) {
    return [true, { authorization }]
  } else {
    return [false, { redirectUrl }]
  }
}

addEventListener('fetch', event => event.respondWith(handleRequest(event)))

async function handleRequest(event) {
  let request = event.request
  const [authorized, { authorization, redirectUrl }] = authorize(event)

  if (authorized && authorization.access_token) {
    request = new Request(request, {
      headers: {
        Authorization: `Bearer ${authorization.access_token}`,
      },
    })
  }

  let response = await fetch(event.request)
  const url = new URL(event.request.url)
  if (url.pathname === '/auth') {
    const authorizedResponse = await handleRedirect(event)
    return new Response(response.body, {
      response,
      ...authorizedResponse,
    })
  }

  if (!authorized) {
    return Response.redirect(redirectUrl)
  }

  return new Response(`<h1>Hello, ${authorization.sub}</h1>`, response)
}
