#[cfg(feature = "heap")]
#[global_allocator]
#[cfg(not(feature = "heap"))]
static ALLOC: dhat::Alloc = dhat::Alloc;

pub mod common;
pub mod tasks;

#[cfg(test)]
pub mod consensus_integration_tests;

#[cfg(test)]
pub mod consensus_pipeline_tests;

#[cfg(test)]
pub mod daemon_integration_tests;

#[cfg(test)]
#[cfg(feature = "devnet-prealloc")]
pub mod mempool_benchmarks;

#[cfg(test)]
#[cfg(feature = "devnet-prealloc")]
pub mod subscribe_benchmarks;

#[cfg(test)]
pub mod rpc_tests;

#[cfg(test)]
pub mod contract_rpc_tests;

#[cfg(test)]
pub mod contract_simulation_tests;

#[cfg(test)]
pub mod contract_grpc_smoke_tests;

#[cfg(test)]
pub mod contract_wrpc_smoke_tests;

#[cfg(test)]
pub mod contract_engine_safety_tests;

#[cfg(test)]
pub mod contract_state_transition_tests;
