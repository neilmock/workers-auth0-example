import { getAssetFromKV } from '@cloudflare/kv-asset-handler'

import { authorize, logout, handleRedirect } from './auth0'
import { hydrateState } from './edge_state'

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

    response = await getAssetFromKV(event)

    if (url.pathname === '/logout') {
      const { headers } = logout(event)
      return headers
        ? new Response(response.body, {
            ...response,
            headers: Object.assign({}, response.headers, headers),
          })
        : Response.redirect(url.origin)
    }

    // hydrate the static site with authorization info from auth0
    // this uses alpine.js and the htmlrewriter engine built into
    // workers. for more info, check out the README
    return new HTMLRewriter()
      .on('script#edge_state', hydrateState(authorization.userInfo))
      .transform(response)

    // to skip any sort of edge-state hydration (see the README) and just
    // return your site, replace the above return call with the line below
    //
    // return response
  } catch (err) {
    return new Response(err.toString())
  }
}
