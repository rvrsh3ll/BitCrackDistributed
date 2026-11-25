# Unit tests
option(BITCRACK_FORCE_FETCH_CATCH2 "Force Fetching Catch2 even on multi-config MSVC generators" OFF)

find_package(Catch2 3 QUIET)

# Workaround: Multi-config MSVC generators cause Catch2 ExternalProject to produce
# VS projects with intermediate PDB paths that result in MSBuild copy errors.
# When Visual Studio generator is used and Catch2 is not already available, we
# avoid fetching/building Catch2 automatically; tests will be skipped unless
# Catch2 is installed on the system or the user enables `BITCRACK_FORCE_FETCH_CATCH2`.
if(NOT Catch2_FOUND)
    if(MSVC AND NOT BITCRACK_FORCE_FETCH_CATCH2)
        message(WARNING "Catch2 not found and using Visual Studio generator; skipping test build (set BITCRACK_FORCE_FETCH_CATCH2=ON to force fetch).")
    else()
        include(FetchContent)
        message(STATUS "Catch2 not found - fetching v3.5.2")
        FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.5.2
            GIT_SHALLOW TRUE
        )
        FetchContent_MakeAvailable(Catch2)
        # If FetchContent created Catch2 targets, ensure MSVC PDB output paths are explicit.
        if(MSVC)
            foreach(_ct Catch2 Catch2WithMain)
                if(TARGET ${_ct})
                    get_target_property(_catch_imported ${_ct} IMPORTED)
                    if(NOT _catch_imported)
                        set_target_properties(${_ct} PROPERTIES
                            COMPILE_PDB_NAME ${_ct}
                            COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/_deps/catch2-build/$<CONFIG>"
                        )
                    endif()
                endif()
            endforeach()

            # Also handle the namespaced alias Catch2::Catch2WithMain if present
            if(TARGET Catch2::Catch2WithMain)
                get_target_property(_alias Catch2::Catch2WithMain ALIASED_TARGET)
                if(_alias AND TARGET ${_alias})
                    get_target_property(_alias_imported ${_alias} IMPORTED)
                    if(NOT _alias_imported)
                        set_target_properties(${_alias} PROPERTIES
                            COMPILE_PDB_NAME ${_alias}
                            COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/_deps/catch2-build/$<CONFIG>"
                        )
                    endif()
                endif()
            endif()
        endif()
    endif()
endif()

if(NOT TARGET Catch2::Catch2WithMain)
    message(STATUS "Catch2::Catch2WithMain target is unavailable - skipping tests")
    return()
endif()

set(TEST_SOURCES
    test_address_generator.cpp
    test_bitcrack_engine.cpp
    test_secp256k1_scan.cpp
    test_engine_found_flow.cpp
    test_standalone_found.cpp
    test_puzzle_table.cpp
    test_network_components.cpp
    test_p2p_keyspace_manager.cpp
    test_psbt_segwit.cpp
    test_wallet_signing.cpp
    test_keyspace_block.cpp
    test_independent_mode.cpp
    test_commit_quorum.cpp
    test_block_persistence.cpp
    test_commit_to_block.cpp
    test_consensus_keyspace_blocks.cpp
    test_chainstore.cpp
    test_sync_fast_path.cpp
    test_startup_checkpoint.cpp
    test_sync_serve_pages.cpp
    test_logger_file.cpp
    # Orphaned consensus/claim/hydration tests
    test_chunk_claim_timeout.cpp
    test_chunk_claim_two_node_approval.cpp
    test_random_chunk_assignment.cpp
    test_hydration.cpp
    test_independent_hydration.cpp
    # select() nfds + owned background thread
    test_network_loopback.cpp
    test_bind_address.cpp
    test_bootstrap_resolve.cpp
    test_data_dir_default.cpp
    test_claim_expiry_no_loop.cpp
    test_peer_link_eviction.cpp
    test_retired_ranges_fast.cpp
    test_scan_complete.cpp
    test_block_assembly_runs.cpp
    test_claim_after_completion.cpp test_claim_only_when_idle.cpp
    test_rescan_ranges.cpp
    # Stable peer IDs + per-peer thread reaping
    test_peer_identity.cpp
    # Clean shutdown on SIGINT/SIGTERM + reward_address resolution
    test_shutdown_reward.cpp
    # Shared HexMath helper
    test_hexmath.cpp
    # Bounded Electrum probe/calls off the constructor path
    test_electrum_timeout.cpp
    # Claim work with one connected peer
    test_two_node_claims.cpp
    # Engine restart race during shutdown
    test_shutdown_race.cpp
    # HELLO before first claim; idle claim retry
    test_hello_before_claim.cpp
    # Random-mode stall after the final chunk
    test_random_mode_stall.cpp
    # Chunk-claim conflicts by range overlap
    test_chunk_conflict_by_range.cpp
    # Chunk-done by (peer, range); claim counters under the claim lock
    test_chunk_done_by_range.cpp
    # Replayed votes finalize claims like live votes
    test_vote_replay_approval.cpp
    # WorkState keyspace blocks read under the lock
    test_workstate_blocks_concurrency.cpp
    # Release a lost peer's claim state (last connection only)
    test_peer_loss_claims.cpp
    # Alias from the uuid when one is configured
    test_alias_from_uuid.cpp
    # Persistent node key + known-peers pinning store
    test_node_identity.cpp
    # Node id kept in node_id.json; node-key alias fallback; config.json restore
    test_node_id_persist.cpp
    # AUTHCHALLENGE/AUTH handshake, peer_auth policy, older-peer fallback
    test_peer_auth_handshake.cpp
    # Fixed-width EC hex encodings (pubkeys, generated private keys)
    test_ec_hex_padding.cpp
    # CHUNKDONE accepted only with the handshake/pinned key; reward gating
    test_chunkdone_auth.cpp
    # CONTRIB / CONTRIBSNAP under the peer-auth rules
    test_contrib_auth.cpp
    # Peer alias re-read per message line
    test_alias_per_message.cpp
    # Wallet signing paths (P2PKH, BIP-143 P2WPKH, PSBT finalize)
    test_wallet_signing_paths.cpp
    # Idempotent rehydration; keep the range when a claim fails
    test_autocontinue_rehydrate.cpp
    # Wallet RPC/address/sweep fixes; opt-in regtest suite ([.regtest])
    test_wallet_rpc_paths.cpp
    test_regtest_wallet.cpp
    # Idle claim retry auto-continues an exhausted range
    test_retry_autocontinue.cpp
    # Strict reward-address validation
    test_address_validation.cpp
    # Owner-only key files; found keys never logged
    test_secret_files.cpp
    # MPC payout path sends the PAYOUT notification
    test_mpc_payout_notify.cpp
    # Reclaim chunks left behind by auto-continue
    test_left_behind.cpp
    # --reward error printed once; --network CLI override
    test_cli_network.cpp
    # Lease on approved claims (stalled holders lose them)
    test_claim_lease.cpp
    # No logger debug noise on stderr
    test_logger_quiet.cpp
    # config.json is 0600
    test_config_permissions.cpp
    # One PAYOUT per payout; the finishing node shows its own event
    test_payout_dedupe.cpp
    # psbt_id is a hash of the whole PSBT
    test_psbt_id.cpp
    # MPC signs with the found key, never the RPC password
    test_mpc_signing_key.cpp
    # MPC payouts off by default; the finder pays out directly
    test_mpc_default_off.cpp
    # Direct payout retries with backoff and resumes after a restart
    test_payout_retry.cpp
    test_logger_callbacks.cpp
    # Standalone engine advances to the next puzzle not solved here
    test_engine_next_puzzle.cpp
    # Engine target/range switch is synchronized
    test_engine_target_swap.cpp
    test_p2p_engine_targets.cpp
    # Peers cannot switch the puzzle; only verified solves do
    test_puzzle_switch_trust.cpp
    test_chainstore_restart.cpp
    test_block_sync.cpp
    test_node_api.cpp
    # HTML dashboard + /history /system /events
    test_dashboard_api.cpp
    # Puzzle address on-chain balance (dashboard Puzzle panel)
    test_puzzle_balance.cpp
    support/TestIsolation.cpp
    # Standalone engine skips puzzles solved here at startup
    test_engine_startup_skip.cpp
    # Stall-aware wall-clock bounds in tests
    test_stall_aware_timer.cpp
    # ResourceMonitor::stop() wakes the monitor thread at once
    test_resource_monitor_stop.cpp
    # ContributionSigner / wire::splitFields extracted from NetworkManager
    test_contribution_signer.cpp
    # Chunk-claim verb payload codec
    test_claim_wire_codec.cpp
    # Chunk-claim types/helpers/state in ChunkClaimBook
    test_chunk_claim_book.cpp
    # Claim decisions in ClaimBook
    test_claim_book_votes.cpp
    test_claim_accounting.cpp
    # Claim expiry/leases/peer loss in ClaimBook
    test_claim_book_expiry.cpp
    # Claim throttle / isClaimedBy in ClaimBook
    test_claim_book_throttle.cpp
    # Peer-message verb dispatch table
    test_verb_routes.cpp
    # CUDA WP1: host/device base-field math (bcdgpu::Fe) vs OpenSSL BIGNUM
    test_gpu_field.cpp
    # CUDA WP2: host/device secp256k1 EC point ops (bcdgpu::Gej) vs OpenSSL + CPU kernel
    test_gpu_ec.cpp
    # CUDA WP3: host/device hashing, full per-key derivation + sorted target match
    test_gpu_hash.cpp
    test_gpu_scan.cpp
    # CUDA WP3: real GPU device test (auto-skips without a CUDA GPU)
    test_gpu_device.cpp
    # GPU worker chunk accounting (host stand-in for the kernel, no GPU needed)
    test_gpu_worker.cpp
    test_gpu_only.cpp
    # GPU nodes claim chunks sized from their measured rate
    test_chunk_sizing.cpp
    test_keyspace_api.cpp
    test_payout_split.cpp
    test_claim_span.cpp
    test_chain_split.cpp
    test_consensus_v4.cpp
)

add_executable(bitcrack_tests ${TEST_SOURCES})

target_link_libraries(bitcrack_tests PRIVATE
    BitCrackCore
    Catch2::Catch2WithMain
)

# Small helper runner that tests file logging in isolation (avoids cross-test interference)
add_executable(logger_file_runner logger_file_runner.cpp)
add_dependencies(logger_file_runner BitCrackCore)
target_link_libraries(logger_file_runner PRIVATE BitCrackCore)

if(TARGET GPUKernels)
    target_link_libraries(bitcrack_tests PRIVATE GPUKernels)
endif()

if(TARGET NetworkLayer)
    target_link_libraries(bitcrack_tests PRIVATE NetworkLayer)
endif()

# The CLI test runs the real executable.
# (bitcrack-distributed is defined after add_subdirectory(tests); both
# references below are resolved at generate time.)
add_dependencies(bitcrack_tests bitcrack-distributed)
target_compile_definitions(bitcrack_tests PRIVATE BITCRACK_MAIN_BINARY="$<TARGET_FILE:bitcrack-distributed>")
target_compile_definitions(bitcrack_tests PRIVATE BITCRACK_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

target_include_directories(bitcrack_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/tests
)

set_target_properties(bitcrack_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

add_custom_target(run_tests
    COMMAND bitcrack_tests
    DEPENDS bitcrack_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running unit tests"
)