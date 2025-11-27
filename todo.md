Todo:

# CLI:
The CLI wallet is not yet complete.

Both methods for verified and signed transactions should be available.

1. Construct and sign the transaction in the CLI (own Systeme)
2. Direct contract requests via RPC


# Signature Script:
1. The unsigned transaction has:

signature_script: vec![] (empty)
sig_op_count: 0 (on Simnet) or sig_op_count: 1 (should be on Mainnet)

However: The signature is still missing!

# Switches und Bridges
Switching all functions to Mainnet; some connections are still missing, which were switched due to Simnet and Rust tests.

# Contracts: 
Revise token and NFT contracts again.
Extend contracts must be RWA compatible.
Mini contracts should also include max supply, start supply, and decimal options.
Staking could be completely removed, since it comes on-chain without contract. We could use the current code as a basis.

#Payload
1. Pay per Byte integration

# Optimizations:
Missing contract submissions should be removed from the mempool immediately upon the first failure. State is missing errors. 
The activation of individual contracts, payload size and statesize, should be in the param.rs

# Later:
1. Remove comments and improve the commenting. There's currently too much clutter.
2. Remove unused imports.
3. Some tests are no longer valid since the switch to the mainnet; revise relevant tests and remove unnecessary ones. All tests that were previously passed are no longer needed.

# Questionable:
Do we need the extra mining software? Because the CLI/wallet can mine tokens anyway.
If so, then we would have to integrate a wallet system, which would then be the same as the CLI/wallet, right?

# Info:
The first hard fork will only activate the following smart contracts (Token Extend, Token Mini, Mining Token, NFT Extend, NFT Mini); the others do not need to be wired up and can continue as they are.
We will further prepare, reprogram, and connect everything during the next hard fork. The VM will be introduced in the final hard fork.
############

@cryptis:
Im handling the CLI and the signing/wiring to the mainnet; please, no one else. Last time, @Proton helped with it, unnecessary duplicate functions were created. 
And Ive lost track of things. So keep your hands off the wallet system, the signatures, and the mainnet wiring.

Info: Whoever is editing the comments, please always write in the "we" form. This is the clearest way to read them.


