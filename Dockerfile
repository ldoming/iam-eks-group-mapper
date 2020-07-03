FROM python:3.9.0a3-alpine3.10 as builder
RUN apk update && apk add --no-cache curl
RUN curl -o aws-iam-authenticator https://amazon-eks.s3-us-west-2.amazonaws.com/1.14.6/2019-08-22/bin/linux/amd64/aws-iam-authenticator \
    && chmod +x ./aws-iam-authenticator

FROM python:3.9.0a3-alpine3.10
RUN apk update \
    && apk add --no-cache build-base \
      openldap-dev \
    && pip install --upgrade pip \
      boto3 \
      python-ldap \
      pyyaml \
      kubernetes
COPY src /src
COPY --from=builder /aws-iam-authenticator /usr/bin/
ENV PATH=$PATH:/src