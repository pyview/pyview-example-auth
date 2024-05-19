FROM python:3.11-alpine as build

RUN apk add build-base libffi-dev
RUN pip install poetry
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    PYTHONUNBUFFERED=1


WORKDIR /app
COPY . .

RUN poetry install --no-root --only main --no-cache

FROM python:3.11-alpine as runtime

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=build /app /app

WORKDIR /app/src

CMD [ "uvicorn", "--host",  "0.0.0.0", "pyview_example_auth.app:app" ]
