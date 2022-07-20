# build context
FROM alpine:3.16 AS build

# build the executable
RUN apk add --no-cache build-base cargo git \
  && git clone https://github.com/holochain/hc-rtc-sig.git \
  && cd hc-rtc-sig \
  && cargo build --release

# run context
FROM alpine:3.16

# dependency
RUN apk add --no-cache libgcc

# copy executable from build context
COPY --from=build \
  ./hc-rtc-sig/target/release/hc-rtc-sig-srv /usr/bin/hc-rtc-sig-srv

# set executable as entrypoint
ENTRYPOINT ["hc-rtc-sig-srv"]
