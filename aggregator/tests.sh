RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_mock_chunk_prover -- --nocapture 2>&1 | tee mock_chunk.log

# the following 4 tests takes super long time
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_proof_compression -- --nocapture 2>&1 | tee compression.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_two_layer_proof_compression -- --ignored --nocapture 2>&1 | tee compression2.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_aggregation_circuit -- --ignored --nocapture 2>&1 | tee aggregation.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_e2e -- --ignored --nocapture 2>&1 | tee aggregation.log
