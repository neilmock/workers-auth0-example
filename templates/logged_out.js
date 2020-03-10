export default () => `
<!doctype html>
<html>
  <head>
    <title>Workers Auth0 Example</title>
    <link href="https://unpkg.com/tailwindcss@^1.0/dist/tailwind.min.css" rel="stylesheet">
    <script type="text/javascript">
      const render = () => document.querySelector("#content").style = ""
    </script>
  </head>
  <body class="antialiased font-sans bg-gray-200" onload="render()">
    <div class="max-w-7xl mx-auto py-12 sm:px-6 lg:px-8">
      <div class="max-w-3xl mx-auto">
        <div class="bg-white shadow sm:rounded-lg" id="content" style="display: none">
          <div class="px-4 py-5 sm:p-6">
            <h3 class="text-xl leading-6 font-medium text-gray-900">
              You're logged out!
            </h3>
            <div class="mt-2 max-w-xl text-md leading-5 text-gray-500">
              <p>
                Note that by default, logging back in with Auth0 will happen automatically if your browser stores session information. This is a simulated "logged out" page.
              </p>
            </div>
            <div class="mt-3 text-md leading-5">
              <a href="/" class="font-medium text-indigo-600 hover:text-indigo-500 focus:outline-none focus:underline transition ease-in-out duration-150">
                Log in again &rarr;
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>
`
