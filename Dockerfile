# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY provider ./provider
COPY integration ./integration
RUN ./integration/prepare.sh /build/esignet
WORKDIR /build/esignet/upstream/esignet-service
RUN go mod download && go mod verify
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w" -o /out/esignet ./cmd/esignet

FROM gcr.io/distroless/base-debian12:nonroot@sha256:7f0c72cd138b442ae0deeb69c08b1acf5525439ba251a49ad93c320a061567e5
ARG CANDIDATE_SOURCE_SHA256=unrecorded
ARG CANDIDATE_SOURCE_REVISION=unknown
ARG CANDIDATE_SOURCE_STATE=unrecorded
LABEL org.opencontainers.image.source="https://github.com/jeremi/esignet-relay-authenticator" \
      org.opencontainers.image.version="0.3.0-candidate" \
      org.opencontainers.image.revision=$CANDIDATE_SOURCE_REVISION \
      io.registry.source.sha256=$CANDIDATE_SOURCE_SHA256 \
      io.registry.source.state=$CANDIDATE_SOURCE_STATE \
      io.registry.esignet.source="https://github.com/mosip/esignet" \
      io.registry.esignet.revision="df0d0e771dae16eb2597b8e5b5dc65e70baa7f86" \
      io.registry.esignet.version="2.0.0-beta.1"
WORKDIR /home/mosip
COPY --from=build --chown=65532:65532 /out/esignet /home/mosip/esignet
COPY --from=build --chown=65532:65532 /build/esignet/upstream/esignet-service/data /home/mosip/data
COPY --from=build /build/esignet/upstream/LICENSE /build/esignet/upstream/THIRD-PARTY-NOTICES.txt /licenses/esignet/
ENV DATA_DIR=/home/mosip/data \
    MOSIP_ESIGNET_AUTHN_PROVIDER=breg \
    MOSIP_ESIGNET_AUTH_FLOW_ID=flow-breg-otp \
    KEYMANAGER_KEYSTORE_TYPE=PKCS12
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/home/mosip/esignet"]
