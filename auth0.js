import cookie from 'cookie'

/*
 * Helper to get from an ascii string to a literal byte array.
 * Necessary to get ascii string prepped for base 64 encoding
 */
const asciiToUint8Array = async str => {
  let chars = []
  for (let i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i))
  }
  return new Uint8Array(chars)
}

const str2ab = async str => {
  var buf = new ArrayBuffer(str.length * 2) // 2 bytes for each char
  var bufView = new Uint16Array(buf)
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

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

const generateKey = async () =>
  crypto.subtle.importKey(
    'raw',
    await asciiToUint8Array(AUTH_KEY),
    'AES-GCM',
    true,
    ['encrypt', 'decrypt'],
  )

const decrypt = async ({ data, iv: newIv }) => {
  const retrievedEncrypted = atob(data)
  const iv = new Uint8Array(atob(newIv).split(','))

  // console.log(data)
  // console.log(retrievedEncrypted)

  let decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv, //The initialization vector you used to encrypt
    },
    await generateKey(), //from generateKey or importKey above
    await str2ab(retrievedEncrypted), //ArrayBuffer of the data
  )

  const encryptedArray = Array.from(new Uint8Array(decrypted))
  const encryptedString = encryptedArray
    .map(byte => String.fromCharCode(byte))
    .join('')

  return { data: btoa(encryptedString) }
}

const encrypt = async data => {
  const myData = btoa(JSON.stringify(data))
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',

      //Don't re-use initialization vectors!
      //Always generate a new iv every time your encrypt!
      //Recommended to use 12 bytes length
      iv,
    },
    await generateKey(), //from generateKey or importKey above
    await str2ab(myData), //ArrayBuffer of data you want to encrypt
  )

  const encryptedArray = Array.from(new Uint8Array(encrypted))
  const encryptedString = encryptedArray
    .map(byte => String.fromCharCode(byte))
    .join('')

  // console.log('btoa')
  // console.log(btoa(encryptedString))
  // console.log('btoa')

  return { data: btoa(encryptedString), iv: btoa(iv) }
}

const persistAuth = async exchange => {
  const body = await exchange.json()

  if (body.error) {
    throw new Error(body.error)
  }

  const date = new Date()
  date.setDate(date.getDate() + 1)

  const decoded = JSON.parse(decodeJWT(body.id_token))
  const { data, iv } = await encrypt(body)
  await AUTH_STORE.put('iv:' + decoded.sub, iv)
  await AUTH_STORE.put(decoded.sub, data)

  const headers = {
    Location: '/',
    'Set-cookie': `${cookieKey}=${
      decoded.sub
    }; HttpOnly; SameSite=Lax; Expires=${date.toUTCString()}`,
  }

  return { headers, status: 302 }
}

const redirectUrl = `${auth0.domain}/authorize?response_type=code&client_id=${auth0.clientId}&redirect_uri=${auth0.callbackUrl}&scope=openid%20profile%20email`
const userInfoUrl = `${auth0.domain}/userInfo`

export const handleRedirect = async event => {
  const url = new URL(event.request.url)
  const code = url.searchParams.get('code')
  if (code) {
    return exchangeCode(code)
  }
  return {}
}

const verify = async event => {
  const cookieHeader = event.request.headers.get('Cookie')
  if (cookieHeader && cookieHeader.includes(cookieKey)) {
    const cookies = cookie.parse(cookieHeader)
    if (!cookies[cookieKey]) return {}
    const sub = cookies[cookieKey]

    const iv = await AUTH_STORE.get(`iv:` + sub)
    const data = await AUTH_STORE.get(sub)
    const { data: kvStored } = await decrypt({ data, iv })
    const { access_token: accessToken, id_token: idToken } = JSON.parse(
      kvStored,
    )
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
