set dotenv-load

start:
  PYVIEW_SECRET=`openssl rand -base64 16` cd src && poetry run uvicorn pyview_example_auth.app:app --reload --port 7100

docker-build:
  docker build -t pyview_example_auth .

docker-run:
  docker run -p 8000:8000 pyview_example_auth