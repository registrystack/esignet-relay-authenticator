# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM --platform=$BUILDPLATFORM docker.io/library/node@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS ui-build
ARG ESIGNET_ARCHIVE_URL
ARG ESIGNET_ARCHIVE_SHA256
WORKDIR /src
ADD --checksum=sha256:${ESIGNET_ARCHIVE_SHA256} ${ESIGNET_ARCHIVE_URL} /tmp/esignet.tar.gz
RUN tar -xzf /tmp/esignet.tar.gz --strip-components=1 && rm /tmp/esignet.tar.gz
COPY ui/default-locale.patch ui/dependencies.patch /tmp/
RUN apk add --no-cache git && git apply --check /tmp/default-locale.patch /tmp/dependencies.patch \
    && git apply /tmp/default-locale.patch /tmp/dependencies.patch
WORKDIR /src/oidc-ui
RUN echo 'bf4336641b4a07f3b1e5ad282db9753d5fd3171bbf5ff0268bab345f2d8f79e6  package-lock.json' \
      | sha256sum -c - \
    && npm ci \
    && VITE_API_URL= npm run build

FROM docker.io/library/nginx@sha256:ce2bd4775ed6859d35f47d65401ee9f35f1dd00b32ed05f0ce38b68aa1830195
ARG ESIGNET_COMMIT
ARG CANDIDATE_SOURCE_SHA256=unrecorded
ARG CANDIDATE_SOURCE_REVISION=unknown
ARG CANDIDATE_SOURCE_STATE=unrecorded
ARG CANDIDATE_VERSION=unreleased
LABEL org.opencontainers.image.source="https://github.com/registrystack/esignet-relay-authenticator" \
      org.opencontainers.image.version=$CANDIDATE_VERSION \
      org.opencontainers.image.revision=$CANDIDATE_SOURCE_REVISION \
      io.registry.source.sha256=$CANDIDATE_SOURCE_SHA256 \
      io.registry.source.state=$CANDIDATE_SOURCE_STATE \
      io.registry.esignet.source="https://github.com/mosip/esignet" \
      io.registry.esignet.revision=$ESIGNET_COMMIT \
      io.registry.esignet.version="2.0.0-beta.1" \
      io.registry.esignet.ui.lock.sha256="bf4336641b4a07f3b1e5ad282db9753d5fd3171bbf5ff0268bab345f2d8f79e6"
COPY --from=ui-build /src/oidc-ui/dist /usr/share/nginx/html
COPY --from=ui-build /src/LICENSE /src/THIRD-PARTY-NOTICES.txt /licenses/esignet/
COPY ui/nginx.conf /etc/nginx/esignet-ui.conf
USER 101:101
EXPOSE 3000
ENTRYPOINT ["nginx"]
CMD ["-c", "/etc/nginx/esignet-ui.conf", "-g", "daemon off;"]
