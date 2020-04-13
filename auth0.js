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

  return persistAuth(
    await fetch(AUTH0_DOMAIN + '/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    }),
  )
}

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

const persistAuth = async exchange => {
  const body = await exchange.json()

  if (body.error) {
    throw new Error(body.error)
  }

  const date = new Date()
  date.setDate(date.getDate() + 1)

  const decoded = JSON.parse(decodeJWT(body.id_token))

  const text = new TextEncoder().encode(`${SALT}-${decoded.sub}`)
  const digest = await crypto.subtle.digest({ name: 'SHA-256' }, text)
  const digestArray = new Uint8Array(digest)
  const id = btoa(String.fromCharCode.apply(null, digestArray))

  await AUTH_STORE.put(id, JSON.stringify(body))

  const headers = {
    Location: '/',
    'Set-cookie': `${cookieKey}=${id}; HttpOnly; SameSite=Lax; Expires=${date.toUTCString()}`,
  }

  return { headers, status: 302 }
}

const redirectUrl = `${auth0.domain}/authorize?response_type=code&client_id=${auth0.clientId}&redirect_uri=${auth0.callbackUrl}&scope=openid%20profile%20email`
const userInfoUrl = `${auth0.domain}/userInfo`

export const handleRedirect = async event => {
  const url = new URL(event.request.url)
  const code = url.searchParams.get('code')
  if (code) {
    return await exchangeCode(code)
  }
  return {}
}

const verify = async event => {
  const cookieHeader = event.request.headers.get('Cookie')
  if (cookieHeader && cookieHeader.includes(cookieKey)) {
    const cookies = cookie.parse(cookieHeader)
    if (!cookies[cookieKey]) return {}
    const sub = cookies[cookieKey]

    const kvStored = JSON.parse(await AUTH_STORE.get(sub))
    const { access_token: accessToken, id_token: idToken } = kvStored
    const decoded = JSON.parse(decodeJWT(idToken))
    const resp = await fetch(userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    const json = await resp.json()
    if (decoded.sub !== json.sub) {
      throw new Error('Access token is invalid')
    }
    return { accessToken, idToken, userInfo: json }
  }
  return {}
}

export const authorize = async event => {
  const authorization = await verify(event)
  if (authorization.accessToken) {
    return [true, { authorization }]
  } else {
    return [false, { redirectUrl }]
  }
}

export const logout = event => {
  const cookieHeader = event.request.headers.get('Cookie')
  if (cookieHeader && cookieHeader.includes(cookieKey)) {
    return {
      headers: {
        'Set-cookie': `${cookieKey}="";`,
      },
    }
  }
  return {}
}
