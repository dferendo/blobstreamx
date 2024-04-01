#!/bin/bash

# Run the original command
cargo run --bin local_relay --release -- --request-id $REQUEST_ID

# Keep the container running
tail -f /dev/null