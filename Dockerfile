FROM rust:1.90-slim-trixie AS build

RUN USER=root cargo new --bin proton-drive-bridge
RUN apt-get update && apt-get -y --no-install-recommends install pkg-config libssl-dev libsodium-dev golang clang
RUN update-ca-certificates

WORKDIR /app

COPY Cargo.lock Cargo.toml ./
COPY .cargo/config.toml ./.cargo/
COPY bridge/src/ ./bridge/src/
COPY bridge/Cargo.toml ./bridge/
COPY pmapi/src/ ./pmapi/src/
COPY pmapi/Cargo.toml ./pmapi/
COPY unftp-sbe-pd/src/ ./unftp-sbe-pd/src/ 
COPY unftp-sbe-pd/Cargo.toml ./unftp-sbe-pd/
COPY users.json ./

RUN RUSTFLAGS='-C target-cpu=native' cargo build --locked --target-dir ./build --release

FROM debian:trixie-slim
RUN apt-get update && apt-get -y --no-install-recommends install ca-certificates libsodium23 && apt-get clean autoclean && rm -rf /var/lib/{apt,dpkg,cache,log}/
COPY --from=build /app/build/release/proton-drive-bridge /usr/bin/proton-drive-bridge
COPY --from=build /app/users.json /app/

WORKDIR /app

CMD ["/usr/bin/proton-drive-bridge"]