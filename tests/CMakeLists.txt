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
    test_logger_file.cpp
    # Orphaned consensus/claim/hydration tests (PR 0)
    test_chunk_claim_timeout.cpp
    test_chunk_claim_two_node_approval.cpp
    test_random_chunk_assignment.cpp
    test_hydration.cpp
    test_independent_hydration.cpp
    # PR 1: select() nfds + owned background thread
    test_network_loopback.cpp
    test_bootstrap_resolve.cpp
    test_data_dir_default.cpp
    test_claim_expiry_no_loop.cpp
    test_peer_link_eviction.cpp
    test_retired_ranges_fast.cpp
    test_scan_complete.cpp
    test_block_assembly_runs.cpp
    test_claim_after_completion.cpp
    test_rescan_ranges.cpp
    # PR 2: stable peer IDs + per-peer thread reaping
    test_peer_identity.cpp
    # PR 3: clean shutdown on SIGINT/SIGTERM + reward_address resolution
    test_shutdown_reward.cpp
    # PR 4: shared HexMath helper
    test_hexmath.cpp
    # PR 5: bounded Electrum probe/calls off the constructor path
    test_electrum_timeout.cpp
    # PR 7: claim work with one connected peer
    test_two_node_claims.cpp
    # PR 9: engine restart race during shutdown
    test_shutdown_race.cpp
    # PR 10: HELLO before first claim; idle claim retry
    test_hello_before_claim.cpp
    # PR 11: random-mode stall after the final chunk
    test_random_mode_stall.cpp
    # PR 12: chunk-claim conflicts by range overlap
    test_chunk_conflict_by_range.cpp
    # PR 13: chunk-done by (peer, range); claim counters under the claim lock
    test_chunk_done_by_range.cpp
    # PR 14: replayed votes finalize claims like live votes
    test_vote_replay_approval.cpp
    # PR 15: WorkState keyspace blocks read under the lock
    test_workstate_blocks_concurrency.cpp
    # PR 16: release a lost peer's claim state (last connection only)
    test_peer_loss_claims.cpp
    # PR 17: alias from the uuid when one is configured
    test_alias_from_uuid.cpp
    # PR 18: persistent node key + known-peers pinning store
    test_node_identity.cpp
    # PR 19: AUTHCHALLENGE/AUTH handshake, peer_auth policy, older-peer fallback
    test_peer_auth_handshake.cpp
    # PR 21: fixed-width EC hex encodings (pubkeys, generated private keys)
    test_ec_hex_padding.cpp
    # PR 22: CHUNKDONE accepted only with the handshake/pinned key; reward gating
    test_chunkdone_auth.cpp
    # PR 23: CONTRIB / CONTRIBSNAP under the peer-auth rules
    test_contrib_auth.cpp
    # PR 25: peer alias re-read per message line
    test_alias_per_message.cpp
    # PR 26: wallet signing paths (P2PKH, BIP-143 P2WPKH, PSBT finalize)
    test_wallet_signing_paths.cpp
    # PR 27: idempotent rehydration; keep the range when a claim fails
    test_autocontinue_rehydrate.cpp
    # PR 29: wallet RPC/address/sweep fixes; opt-in regtest suite ([.regtest])
    test_wallet_rpc_paths.cpp
    test_regtest_wallet.cpp
    # PR 30: idle claim retry auto-continues an exhausted range
    test_retry_autocontinue.cpp
    # PR 31: strict reward-address validation
    test_address_validation.cpp
    # PR 33: owner-only key files; found keys never logged
    test_secret_files.cpp
    # PR 37: MPC payout path sends the PAYOUT notification
    test_mpc_payout_notify.cpp
    # PR 34: reclaim chunks left behind by auto-continue
    test_left_behind.cpp
    # PR 36: --reward error printed once; --network CLI override
    test_cli_network.cpp
    # PR 42: lease on approved claims (stalled holders lose them)
    test_claim_lease.cpp
    # PR 38: no logger debug noise on stderr
    test_logger_quiet.cpp
    # PR 39: config.json is 0600
    test_config_permissions.cpp
    # PR 41: one PAYOUT per payout; the finishing node shows its own event
    test_payout_dedupe.cpp
    # PR 43: psbt_id is a hash of the whole PSBT
    test_psbt_id.cpp
    # PR 44: MPC signs with the found key, never the RPC password
    test_mpc_signing_key.cpp
    # PR 46: MPC payouts off by default; the finder pays out directly
    test_mpc_default_off.cpp
    # PR 47: direct payout retries with backoff and resumes after a restart
    test_payout_retry.cpp
    test_logger_callbacks.cpp
    # PR 53: standalone engine advances to the next puzzle not solved here
    test_engine_next_puzzle.cpp
    # PR 54: engine target/range switch is synchronized
    test_engine_target_swap.cpp
    test_p2p_engine_targets.cpp
    # PR 80: peers cannot switch the puzzle; only verified solves do
    test_puzzle_switch_trust.cpp
    test_chainstore_restart.cpp
    test_block_sync.cpp
    test_node_api.cpp
    support/TestIsolation.cpp
    # PR 55: standalone engine skips puzzles solved here at startup
    test_engine_startup_skip.cpp
    # PR 58: stall-aware wall-clock bounds in tests
    test_stall_aware_timer.cpp
    # PR 61: ResourceMonitor::stop() wakes the monitor thread at once
    test_resource_monitor_stop.cpp
    # PR 62: ContributionSigner / wire::splitFields extracted from NetworkManager
    test_contribution_signer.cpp
    # PR 63: chunk-claim verb payload codec
    test_claim_wire_codec.cpp
    # PR 64: chunk-claim types/helpers/state in ChunkClaimBook
    test_chunk_claim_book.cpp
    # PR 65: claim decisions in ClaimBook
    test_claim_book_votes.cpp
    # PR 66: claim expiry/leases/peer loss in ClaimBook
    test_claim_book_expiry.cpp
    # PR 67: claim throttle / isClaimedBy in ClaimBook
    test_claim_book_throttle.cpp
    # PR 69: peer-message verb dispatch table
    test_verb_routes.cpp
)

if(GUI_AVAILABLE)
    list(APPEND TEST_SOURCES test_gui_telemetry.cpp test_gui_log_thread.cpp
        test_gui_close_shutdown.cpp)  # PR 56
    message(STATUS "Including GUI telemetry test (requires Qt)")
endif()

add_executable(bitcrack_tests ${TEST_SOURCES})

target_link_libraries(bitcrack_tests PRIVATE
    BitCrackCore
    Catch2::Catch2WithMain
)

# Small helper runner that tests file logging in isolation (avoids cross-test interference)
add_executable(logger_file_runner logger_file_runner.cpp)
add_dependencies(logger_file_runner BitCrackCore)
target_link_libraries(logger_file_runner PRIVATE BitCrackCore)

if(GUI_AVAILABLE)
    target_link_libraries(bitcrack_tests PRIVATE BitCrackGUI)
    # Link Qt Widgets as MainWindow uses Qt Widgets
    set(_qt_prefix Qt${BITCRACK_QT_VERSION})
    target_link_libraries(bitcrack_tests PRIVATE ${_qt_prefix}::Widgets ${_qt_prefix}::Core ${_qt_prefix}::Network)
endif()

if(TARGET GPUKernels)
    target_link_libraries(bitcrack_tests PRIVATE GPUKernels)
endif()

if(TARGET NetworkLayer)
    target_link_libraries(bitcrack_tests PRIVATE NetworkLayer)
endif()

# PR 36: the CLI test runs the real executable.
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