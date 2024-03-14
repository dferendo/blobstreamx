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

# ENTRYPOINT ["anvil", "--host", "0.0.0.0", "--state", "./data/"]
