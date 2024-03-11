# --------------------------------------------------------
# Builder
# --------------------------------------------------------

# Use the latest foundry image
FROM rust:1.76.0

WORKDIR /app

# Build files
COPY . .

# Build the BlobstreamX operator. No circuits required since everything is ran using Succinct API.
RUN cargo build --bin blobstreamx --release

# --------------------------------------------------------
# Runner
# --------------------------------------------------------

# TODO: separate builder from runner to make resultant image more lightweight

# EXPOSE 8545

# ENTRYPOINT ["anvil", "--host", "0.0.0.0", "--state", "./data/"]
