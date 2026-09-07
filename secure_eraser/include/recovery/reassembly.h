#ifndef ERASECURE_REASSEMBLY_H
#define ERASECURE_REASSEMBLY_H

#include <stdint.h>
#include <stddef.h>
#include "common/error.h"
#include "common/types.h"

typedef struct ReassemblyOptions {
    uint32_t max_backtracks;
    uint32_t galloping_step;
    double locality_weight;
    double validator_weight;
    double structural_weight;
    double reservation_penalty;
} ReassemblyOptions;

/**
 * @brief Initialize reassembly options with default values.
 *
 * @param opts Pointer to the ReassemblyOptions to initialize.
 */
void reassembly_options_init(ReassemblyOptions *opts);

/**
 * @brief Score a candidate block for reassembly based on locality, structural, and validation scores.
 *
 * @param fm Pointer to FileMirror.
 * @param bm Pointer to Blockmap.
 * @param candidate_actual_block The candidate block number.
 * @param candidate_pos The candidate position.
 * @param cs Pointer to CarveState.
 * @param opts Pointer to ReassemblyOptions.
 * @param score_out Pointer to output the calculated score.
 * @return ErasecureError Success or error code.
 */
ErasecureError reassembly_score_block(const FileMirror *fm, const Blockmap *bm, uint64_t candidate_actual_block, uint64_t candidate_pos, const CarveState *cs, const ReassemblyOptions *opts, double *score_out);

/**
 * @brief Perform a single step of reassembly.
 *
 * @param cs Pointer to CarveState.
 * @param fm Pointer to FileMirror.
 * @param bm Pointer to Blockmap.
 * @param ftd Pointer to FileTypeDescriptor.
 * @param opts Pointer to ReassemblyOptions.
 * @return ErasecureError Success or error code.
 */
ErasecureError reassembly_step(CarveState *cs, FileMirror *fm, Blockmap *bm, const FileTypeDescriptor *ftd, const ReassemblyOptions *opts);

/**
 * @brief Tentatively append multiple consecutive sequential blocks and validate.
 *
 * @param cs Pointer to CarveState.
 * @param fm Pointer to FileMirror.
 * @param bm Pointer to Blockmap.
 * @param ftd Pointer to FileTypeDescriptor.
 * @param step_size Number of consecutive blocks to attempt to append.
 * @param blocks_added Pointer to output the number of successfully added blocks.
 * @return ErasecureError Success or error code.
 */
ErasecureError reassembly_gallop(CarveState *cs, FileMirror *fm, Blockmap *bm, const FileTypeDescriptor *ftd, uint32_t step_size, uint32_t *blocks_added);

/**
 * @brief Backtrack by popping blocks from the current state.
 *
 * @param cs Pointer to CarveState.
 * @param bm Pointer to Blockmap.
 * @param target_length The target length to reach after backtracking.
 * @return ErasecureError Success or error code.
 */
ErasecureError reassembly_backtrack(CarveState *cs, Blockmap *bm, size_t target_length);

#endif /* ERASECURE_REASSEMBLY_H */
