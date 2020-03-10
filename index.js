import { authorize, logout, handleRedirect } from './auth0'

import index from './templates/index'
import logged_out from './templates/logged_out'

addEventListener('fetch', event => event.respondWith(handleRequest(event)))

const config = {
  originless: true,
}

async function handleRequest(event) {
  try {
    let request = event.request
    const [authorized, { authorization, redirectUrl }] = await authorize(event)
    if (authorized && authorization.accessToken) {
      request = new Request(request, {
        headers: {
          Authorization: `Bearer ${authorization.accessToken}`,
        },
      })
    }

    let response = config.originless
      ? new Response(null)
      : await fetch(event.request)

    const url = new URL(event.request.url)
    if (url.pathname === '/logout') {
      const { headers } = logout(event)
      return headers
        ? new Response(logged_out(), {
            headers: Object.assign({}, headers, {
              'Content-type': 'text/html',
            }),
          })
        : Response.redirect(url.origin)
    }

    if (url.pathname === '/auth') {
      const authorizedResponse = await handleRedirect(event)
      response = new Response(response.body, {
        response,
        ...authorizedResponse,
      })
      return response
    }

    if (!authorized) {
      return Response.redirect(redirectUrl)
    }

    return config.originless
      ? new Response(index({ userInfo: authorization.userInfo }), {
          headers: { 'Content-type': 'text/html' },
        })
      : response
  } catch (err) {
    return new Response(err.toString())
  }
}
