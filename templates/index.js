export default ({ userInfo }) => `
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
              Hey, ${userInfo.name}!
            </h3>
            <div class="mt-2 max-w-xl text-md leading-5 text-gray-500">
              <p>
                This is an <strong>authorized</strong> Workers application using Auth0.
              </p>
            </div>
            <div class="mt-3 text-md leading-5">
              <a href="https://github.com/signalnerve/workers-auth0-example" class="font-medium text-indigo-600 hover:text-indigo-500 focus:outline-none focus:underline transition ease-in-out duration-150">
                See the open-source code to learn more about this code &rarr;
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>
`
