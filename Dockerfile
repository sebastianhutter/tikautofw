FROM python:alpine
MAINTAINER sebastian hutter <mail@sebastian-hutter.ch>

ADD build/app/requirements.txt /app/requirements.txt

RUN apk --no-cache add --virtual build-dependencies build-base gcc binutils linux-headers libffi-dev openssl-dev && \
  apk add --no-cache tini libffi && \
  pip install --upgrade -r /app/requirements.txt && \
  apk del build-dependencies

ENV PYTHONPATH="${PYTHONPATH}:/app"
ADD build/app /app

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/python3", "/app/autofw.py"]
