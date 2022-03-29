# P217 Parameters generation

## Constants in C code
1. MASK\_ALICE, MASK\_BOB seem to be used to Mask the secret key (only used for SIKE, we can probably skip)
2. Need to figure out parameters for isogeny tree computations (MAX_INT_POINTS_ALICE, MAX_INT_POINTS_BOB, MAX_Alice, MAX_Bob)
3. MSG_BYTES should probably be smaller for efficiency

##
1. Ok in `MULADD64x448` we seem to xoring a register which is not used
