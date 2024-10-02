# pyview auth example

This is a small [pyview](https://github.com/ogrodnek/pyview) example project that demonstrates how to integrate [authlib](https://docs.authlib.org/en/latest/) with pyview.

## Development

This project uses [Poetry](https://python-poetry.org/) to manage dependencies and [just](https://github.com/casey/just) as a comamnd runner.

## Auth configuration

The example is set up to use google sign in, you will need to create a google project and set up the credentials in the google developer console.

This example is expecting the following environment variables to be set:

```sh
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
```

Or if you are using just, you can create a `.env` file in the root of the project with the following content:

```sh
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
```

### Dependency Setup

```sh
poetry install
```

### Running

```sh
just
```

This will run the example pyview project using uvicorn with hot reloading.
