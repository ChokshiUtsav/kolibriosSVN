/*
 * Copyright © 2006,2008,2011 Intel Corporation
 * Copyright © 2007 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *    Wang Zhenyu <zhenyu.z.wang@sna.com>
 *    Eric Anholt <eric@anholt.net>
 *    Carl Worth <cworth@redhat.com>
 *    Keith Packard <keithp@keithp.com>
 *    Chris Wilson <chris@chris-wilson.co.uk>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sna.h"
#include "sna_reg.h"
#include "sna_render.h"
#include "sna_render_inline.h"
//#include "sna_video.h"

#include "brw/brw.h"
#include "gen5_render.h"
#include "gen4_source.h"
#include "gen4_vertex.h"

#define NO_COMPOSITE 0
#define NO_COMPOSITE_SPANS 0

#define PREFER_BLT_FILL 1

#define DBG_NO_STATE_CACHE 0
#define DBG_NO_SURFACE_CACHE 0

#define MAX_3D_SIZE 8192

#define GEN5_GRF_BLOCKS(nreg)    ((nreg + 15) / 16 - 1)

/* Set up a default static partitioning of the URB, which is supposed to
 * allow anything we would want to do, at potentially lower performance.
 */
#define URB_CS_ENTRY_SIZE     1
#define URB_CS_ENTRIES	      0

#define URB_VS_ENTRY_SIZE     1
#define URB_VS_ENTRIES	      256 /* minimum of 8 */

#define URB_GS_ENTRY_SIZE     0
#define URB_GS_ENTRIES	      0

#define URB_CLIP_ENTRY_SIZE   0
#define URB_CLIP_ENTRIES      0

#define URB_SF_ENTRY_SIZE     2
#define URB_SF_ENTRIES	      64

/*
 * this program computes dA/dx and dA/dy for the texture coordinates along
 * with the base texture coordinate. It was extracted from the Mesa driver
 */

#define SF_KERNEL_NUM_GRF  16
#define SF_MAX_THREADS	   48

#define PS_KERNEL_NUM_GRF   32
#define PS_MAX_THREADS	    72

static const uint32_t ps_kernel_packed_static[][4] = {
#include "exa_wm_xy.g5b"
#include "exa_wm_src_affine.g5b"
#include "exa_wm_src_sample_argb.g5b"
#include "exa_wm_yuv_rgb.g5b"
#include "exa_wm_write.g5b"
};

static const uint32_t ps_kernel_planar_static[][4] = {
#include "exa_wm_xy.g5b"
#include "exa_wm_src_affine.g5b"
#include "exa_wm_src_sample_planar.g5b"
#include "exa_wm_yuv_rgb.g5b"
#include "exa_wm_write.g5b"
};

#define NOKERNEL(kernel_enum, func, masked) \
    [kernel_enum] = {func, 0, masked}
#define KERNEL(kernel_enum, kernel, masked) \
    [kernel_enum] = {&kernel, sizeof(kernel), masked}
static const struct wm_kernel_info {
	const void *data;
	unsigned int size;
	bool has_mask;
} wm_kernels[] = {
	NOKERNEL(WM_KERNEL, brw_wm_kernel__affine, false),
	NOKERNEL(WM_KERNEL_P, brw_wm_kernel__projective, false),

	NOKERNEL(WM_KERNEL_MASK, brw_wm_kernel__affine_mask, true),
	NOKERNEL(WM_KERNEL_MASK_P, brw_wm_kernel__projective_mask, true),

	NOKERNEL(WM_KERNEL_MASKCA, brw_wm_kernel__affine_mask_ca, true),
	NOKERNEL(WM_KERNEL_MASKCA_P, brw_wm_kernel__projective_mask_ca, true),

	NOKERNEL(WM_KERNEL_MASKSA, brw_wm_kernel__affine_mask_sa, true),
	NOKERNEL(WM_KERNEL_MASKSA_P, brw_wm_kernel__projective_mask_sa, true),

	NOKERNEL(WM_KERNEL_OPACITY, brw_wm_kernel__affine_opacity, true),
	NOKERNEL(WM_KERNEL_OPACITY_P, brw_wm_kernel__projective_opacity, true),

	KERNEL(WM_KERNEL_VIDEO_PLANAR, ps_kernel_planar_static, false),
	KERNEL(WM_KERNEL_VIDEO_PACKED, ps_kernel_packed_static, false),
};
#undef KERNEL

static const struct blendinfo {
	bool src_alpha;
	uint32_t src_blend;
	uint32_t dst_blend;
} gen5_blend_op[] = {
	/* Clear */	{0, GEN5_BLENDFACTOR_ZERO, GEN5_BLENDFACTOR_ZERO},
	/* Src */	{0, GEN5_BLENDFACTOR_ONE, GEN5_BLENDFACTOR_ZERO},
	/* Dst */	{0, GEN5_BLENDFACTOR_ZERO, GEN5_BLENDFACTOR_ONE},
	/* Over */	{1, GEN5_BLENDFACTOR_ONE, GEN5_BLENDFACTOR_INV_SRC_ALPHA},
	/* OverReverse */ {0, GEN5_BLENDFACTOR_INV_DST_ALPHA, GEN5_BLENDFACTOR_ONE},
	/* In */	{0, GEN5_BLENDFACTOR_DST_ALPHA, GEN5_BLENDFACTOR_ZERO},
	/* InReverse */	{1, GEN5_BLENDFACTOR_ZERO, GEN5_BLENDFACTOR_SRC_ALPHA},
	/* Out */	{0, GEN5_BLENDFACTOR_INV_DST_ALPHA, GEN5_BLENDFACTOR_ZERO},
	/* OutReverse */ {1, GEN5_BLENDFACTOR_ZERO, GEN5_BLENDFACTOR_INV_SRC_ALPHA},
	/* Atop */	{1, GEN5_BLENDFACTOR_DST_ALPHA, GEN5_BLENDFACTOR_INV_SRC_ALPHA},
	/* AtopReverse */ {1, GEN5_BLENDFACTOR_INV_DST_ALPHA, GEN5_BLENDFACTOR_SRC_ALPHA},
	/* Xor */	{1, GEN5_BLENDFACTOR_INV_DST_ALPHA, GEN5_BLENDFACTOR_INV_SRC_ALPHA},
	/* Add */	{0, GEN5_BLENDFACTOR_ONE, GEN5_BLENDFACTOR_ONE},
};

/**
 * Highest-valued BLENDFACTOR used in gen5_blend_op.
 *
 * This leaves out GEN5_BLENDFACTOR_INV_DST_COLOR,
 * GEN5_BLENDFACTOR_INV_CONST_{COLOR,ALPHA},
 * GEN5_BLENDFACTOR_INV_SRC1_{COLOR,ALPHA}
 */
#define GEN5_BLENDFACTOR_COUNT (GEN5_BLENDFACTOR_INV_DST_ALPHA + 1)

#define BLEND_OFFSET(s, d) \
	(((s) * GEN5_BLENDFACTOR_COUNT + (d)) * 64)

#define SAMPLER_OFFSET(sf, se, mf, me, k) \
	((((((sf) * EXTEND_COUNT + (se)) * FILTER_COUNT + (mf)) * EXTEND_COUNT + (me)) * KERNEL_COUNT + (k)) * 64)

static bool
gen5_emit_pipelined_pointers(struct sna *sna,
			     const struct sna_composite_op *op,
			     int blend, int kernel);

#define OUT_BATCH(v) batch_emit(sna, v)
#define OUT_VERTEX(x,y) vertex_emit_2s(sna, x,y)
#define OUT_VERTEX_F(v) vertex_emit(sna, v)

static inline bool too_large(int width, int height)
{
	return width > MAX_3D_SIZE || height > MAX_3D_SIZE;
}

static int
gen5_choose_composite_kernel(int op, bool has_mask, bool is_ca, bool is_affine)
{
	int base;

	if (has_mask) {
		if (is_ca) {
			if (gen5_blend_op[op].src_alpha)
				base = WM_KERNEL_MASKSA;
			else
				base = WM_KERNEL_MASKCA;
		} else
			base = WM_KERNEL_MASK;
	} else
		base = WM_KERNEL;

	return base + !is_affine;
}

static bool gen5_magic_ca_pass(struct sna *sna,
			       const struct sna_composite_op *op)
{
	struct gen5_render_state *state = &sna->render_state.gen5;

	if (!op->need_magic_ca_pass)
		return false;

	assert(sna->render.vertex_index > sna->render.vertex_start);

	DBG(("%s: CA fixup\n", __FUNCTION__));
	assert(op->mask.bo != NULL);
	assert(op->has_component_alpha);

	gen5_emit_pipelined_pointers
		(sna, op, PictOpAdd,
		 gen5_choose_composite_kernel(PictOpAdd,
					      true, true, op->is_affine));

	OUT_BATCH(GEN5_3DPRIMITIVE |
		  GEN5_3DPRIMITIVE_VERTEX_SEQUENTIAL |
		  (_3DPRIM_RECTLIST << GEN5_3DPRIMITIVE_TOPOLOGY_SHIFT) |
		  (0 << 9) |
		  4);
	OUT_BATCH(sna->render.vertex_index - sna->render.vertex_start);
	OUT_BATCH(sna->render.vertex_start);
	OUT_BATCH(1);	/* single instance */
	OUT_BATCH(0);	/* start instance location */
	OUT_BATCH(0);	/* index buffer offset, ignored */

	state->last_primitive = sna->kgem.nbatch;
	return true;
}

static uint32_t gen5_get_blend(int op,
			       bool has_component_alpha,
			       uint32_t dst_format)
{
	uint32_t src, dst;

    src = GEN5_BLENDFACTOR_ONE; //gen6_blend_op[op].src_blend;
    dst = GEN5_BLENDFACTOR_INV_SRC_ALPHA; //gen6_blend_op[op].dst_blend;
#if 0
	/* If there's no dst alpha channel, adjust the blend op so that we'll treat
	 * it as always 1.
	 */
	if (PICT_FORMAT_A(dst_format) == 0) {
		if (src == GEN5_BLENDFACTOR_DST_ALPHA)
			src = GEN5_BLENDFACTOR_ONE;
		else if (src == GEN5_BLENDFACTOR_INV_DST_ALPHA)
			src = GEN5_BLENDFACTOR_ZERO;
	}

	/* If the source alpha is being used, then we should only be in a
	 * case where the source blend factor is 0, and the source blend
	 * value is the mask channels multiplied by the source picture's alpha.
	 */
	if (has_component_alpha && gen5_blend_op[op].src_alpha) {
		if (dst == GEN5_BLENDFACTOR_SRC_ALPHA)
			dst = GEN5_BLENDFACTOR_SRC_COLOR;
		else if (dst == GEN5_BLENDFACTOR_INV_SRC_ALPHA)
			dst = GEN5_BLENDFACTOR_INV_SRC_COLOR;
	}
#endif

	DBG(("blend op=%d, dst=%x [A=%d] => src=%d, dst=%d => offset=%x\n",
	     op, dst_format, PICT_FORMAT_A(dst_format),
	     src, dst, BLEND_OFFSET(src, dst)));
	return BLEND_OFFSET(src, dst);
}

static uint32_t gen5_get_card_format(PictFormat format)
{
	switch (format) {
	default:
		return -1;
	case PICT_a8r8g8b8:
		return GEN5_SURFACEFORMAT_B8G8R8A8_UNORM;
	case PICT_x8r8g8b8:
		return GEN5_SURFACEFORMAT_B8G8R8X8_UNORM;
	case PICT_a8:
		return GEN5_SURFACEFORMAT_A8_UNORM;
	}
}

static uint32_t gen5_get_dest_format(PictFormat format)
{
	switch (format) {
	default:
		return -1;
	case PICT_a8r8g8b8:
	case PICT_x8r8g8b8:
		return GEN5_SURFACEFORMAT_B8G8R8A8_UNORM;
	case PICT_a8:
		return GEN5_SURFACEFORMAT_A8_UNORM;
	}
}
typedef struct gen5_surface_state_padded {
	struct gen5_surface_state state;
	char pad[32 - sizeof(struct gen5_surface_state)];
} gen5_surface_state_padded;

static void null_create(struct sna_static_stream *stream)
{
	/* A bunch of zeros useful for legacy border color and depth-stencil */
	sna_static_stream_map(stream, 64, 64);
}

static void
sampler_state_init(struct gen5_sampler_state *sampler_state,
		   sampler_filter_t filter,
		   sampler_extend_t extend)
{
	sampler_state->ss0.lod_preclamp = 1;	/* GL mode */

	/* We use the legacy mode to get the semantics specified by
	 * the Render extension. */
	sampler_state->ss0.border_color_mode = GEN5_BORDER_COLOR_MODE_LEGACY;

	switch (filter) {
	default:
	case SAMPLER_FILTER_NEAREST:
		sampler_state->ss0.min_filter = GEN5_MAPFILTER_NEAREST;
		sampler_state->ss0.mag_filter = GEN5_MAPFILTER_NEAREST;
		break;
	case SAMPLER_FILTER_BILINEAR:
		sampler_state->ss0.min_filter = GEN5_MAPFILTER_LINEAR;
		sampler_state->ss0.mag_filter = GEN5_MAPFILTER_LINEAR;
		break;
	}

	switch (extend) {
	default:
	case SAMPLER_EXTEND_NONE:
		sampler_state->ss1.r_wrap_mode = GEN5_TEXCOORDMODE_CLAMP_BORDER;
		sampler_state->ss1.s_wrap_mode = GEN5_TEXCOORDMODE_CLAMP_BORDER;
		sampler_state->ss1.t_wrap_mode = GEN5_TEXCOORDMODE_CLAMP_BORDER;
		break;
	case SAMPLER_EXTEND_REPEAT:
		sampler_state->ss1.r_wrap_mode = GEN5_TEXCOORDMODE_WRAP;
		sampler_state->ss1.s_wrap_mode = GEN5_TEXCOORDMODE_WRAP;
		sampler_state->ss1.t_wrap_mode = GEN5_TEXCOORDMODE_WRAP;
		break;
	case SAMPLER_EXTEND_PAD:
		sampler_state->ss1.r_wrap_mode = GEN5_TEXCOORDMODE_CLAMP;
		sampler_state->ss1.s_wrap_mode = GEN5_TEXCOORDMODE_CLAMP;
		sampler_state->ss1.t_wrap_mode = GEN5_TEXCOORDMODE_CLAMP;
		break;
	case SAMPLER_EXTEND_REFLECT:
		sampler_state->ss1.r_wrap_mode = GEN5_TEXCOORDMODE_MIRROR;
		sampler_state->ss1.s_wrap_mode = GEN5_TEXCOORDMODE_MIRROR;
		sampler_state->ss1.t_wrap_mode = GEN5_TEXCOORDMODE_MIRROR;
		break;
	}
}

static uint32_t
gen5_tiling_bits(uint32_t tiling)
{
	switch (tiling) {
	default: assert(0);
	case I915_TILING_NONE: return 0;
	case I915_TILING_X: return GEN5_SURFACE_TILED;
	case I915_TILING_Y: return GEN5_SURFACE_TILED | GEN5_SURFACE_TILED_Y;
	}
}

/**
 * Sets up the common fields for a surface state buffer for the given
 * picture in the given surface state buffer.
 */
static uint32_t
gen5_bind_bo(struct sna *sna,
	     struct kgem_bo *bo,
	     uint32_t width,
	     uint32_t height,
	     uint32_t format,
	     bool is_dst)
{
	uint32_t domains;
	uint16_t offset;
	uint32_t *ss;

	/* After the first bind, we manage the cache domains within the batch */
	if (!DBG_NO_SURFACE_CACHE) {
		offset = kgem_bo_get_binding(bo, format);
		if (offset) {
			if (is_dst)
				kgem_bo_mark_dirty(bo);
			return offset * sizeof(uint32_t);
		}
	}

	offset = sna->kgem.surface -=
		sizeof(struct gen5_surface_state_padded) / sizeof(uint32_t);
	ss = sna->kgem.batch + offset;

	ss[0] = (GEN5_SURFACE_2D << GEN5_SURFACE_TYPE_SHIFT |
		 GEN5_SURFACE_BLEND_ENABLED |
		 format << GEN5_SURFACE_FORMAT_SHIFT);

	if (is_dst)
		domains = I915_GEM_DOMAIN_RENDER << 16 | I915_GEM_DOMAIN_RENDER;
	else
		domains = I915_GEM_DOMAIN_SAMPLER << 16;
	ss[1] = kgem_add_reloc(&sna->kgem, offset + 1, bo, domains, 0);

	ss[2] = ((width - 1)  << GEN5_SURFACE_WIDTH_SHIFT |
		 (height - 1) << GEN5_SURFACE_HEIGHT_SHIFT);
	ss[3] = (gen5_tiling_bits(bo->tiling) |
		 (bo->pitch - 1) << GEN5_SURFACE_PITCH_SHIFT);
	ss[4] = 0;
	ss[5] = 0;

	kgem_bo_set_binding(bo, format, offset);

	DBG(("[%x] bind bo(handle=%d, addr=%d), format=%d, width=%d, height=%d, pitch=%d, tiling=%d -> %s\n",
	     offset, bo->handle, ss[1],
	     format, width, height, bo->pitch, bo->tiling,
	     domains & 0xffff ? "render" : "sampler"));

	return offset * sizeof(uint32_t);
}

static void gen5_emit_vertex_buffer(struct sna *sna,
				    const struct sna_composite_op *op)
{
	int id = op->u.gen5.ve_id;

	assert((sna->render.vb_id & (1 << id)) == 0);

	OUT_BATCH(GEN5_3DSTATE_VERTEX_BUFFERS | 3);
	OUT_BATCH(id << VB0_BUFFER_INDEX_SHIFT | VB0_VERTEXDATA |
		  (4*op->floats_per_vertex << VB0_BUFFER_PITCH_SHIFT));
	assert(sna->render.nvertex_reloc < ARRAY_SIZE(sna->render.vertex_reloc));
	sna->render.vertex_reloc[sna->render.nvertex_reloc++] = sna->kgem.nbatch;
	OUT_BATCH(0);
	OUT_BATCH(~0); /* max address: disabled */
	OUT_BATCH(0);

	sna->render.vb_id |= 1 << id;
}

static void gen5_emit_primitive(struct sna *sna)
{
	if (sna->kgem.nbatch == sna->render_state.gen5.last_primitive) {
		sna->render.vertex_offset = sna->kgem.nbatch - 5;
		return;
	}

	OUT_BATCH(GEN5_3DPRIMITIVE |
		  GEN5_3DPRIMITIVE_VERTEX_SEQUENTIAL |
		  (_3DPRIM_RECTLIST << GEN5_3DPRIMITIVE_TOPOLOGY_SHIFT) |
		  (0 << 9) |
		  4);
	sna->render.vertex_offset = sna->kgem.nbatch;
	OUT_BATCH(0);	/* vertex count, to be filled in later */
	OUT_BATCH(sna->render.vertex_index);
	OUT_BATCH(1);	/* single instance */
	OUT_BATCH(0);	/* start instance location */
	OUT_BATCH(0);	/* index buffer offset, ignored */
	sna->render.vertex_start = sna->render.vertex_index;

	sna->render_state.gen5.last_primitive = sna->kgem.nbatch;
}

static bool gen5_rectangle_begin(struct sna *sna,
				 const struct sna_composite_op *op)
{
	int id = op->u.gen5.ve_id;
	int ndwords;

	if (sna_vertex_wait__locked(&sna->render) && sna->render.vertex_offset)
		return true;

	ndwords = op->need_magic_ca_pass ? 20 : 6;
	if ((sna->render.vb_id & (1 << id)) == 0)
		ndwords += 5;

	if (!kgem_check_batch(&sna->kgem, ndwords))
		return false;

	if ((sna->render.vb_id & (1 << id)) == 0)
		gen5_emit_vertex_buffer(sna, op);
	if (sna->render.vertex_offset == 0)
		gen5_emit_primitive(sna);

	return true;
}

static int gen5_get_rectangles__flush(struct sna *sna,
				      const struct sna_composite_op *op)
{
	/* Preventing discarding new vbo after lock contention */
	if (sna_vertex_wait__locked(&sna->render)) {
		int rem = vertex_space(sna);
		if (rem > op->floats_per_rect)
			return rem;
	}

	if (!kgem_check_batch(&sna->kgem, op->need_magic_ca_pass ? 20 : 6))
		return 0;
	if (!kgem_check_reloc_and_exec(&sna->kgem, 2))
		return 0;

	if (sna->render.vertex_offset) {
		gen4_vertex_flush(sna);
		if (gen5_magic_ca_pass(sna, op))
			gen5_emit_pipelined_pointers(sna, op, op->op,
						     op->u.gen5.wm_kernel);
	}

	return gen4_vertex_finish(sna);
}

inline static int gen5_get_rectangles(struct sna *sna,
				      const struct sna_composite_op *op,
				      int want,
				      void (*emit_state)(struct sna *sna,
							 const struct sna_composite_op *op))
{
	int rem;

	assert(want);

start:
	rem = vertex_space(sna);
	if (unlikely(rem < op->floats_per_rect)) {
		DBG(("flushing vbo for %s: %d < %d\n",
		     __FUNCTION__, rem, op->floats_per_rect));
		rem = gen5_get_rectangles__flush(sna, op);
		if (unlikely (rem == 0))
			goto flush;
	}

	if (unlikely(sna->render.vertex_offset == 0)) {
		if (!gen5_rectangle_begin(sna, op))
			goto flush;
		else
			goto start;
	}

	assert(op->floats_per_rect >= vertex_space(sna));
	assert(rem <= vertex_space(sna));
	if (want > 1 && want * op->floats_per_rect > rem)
		want = rem / op->floats_per_rect;

	sna->render.vertex_index += 3*want;
	return want;

flush:
	if (sna->render.vertex_offset) {
		gen4_vertex_flush(sna);
		gen5_magic_ca_pass(sna, op);
	}
	sna_vertex_wait__locked(&sna->render);
	_kgem_submit(&sna->kgem);
	emit_state(sna, op);
	goto start;
}

static uint32_t *
gen5_composite_get_binding_table(struct sna *sna,
				 uint16_t *offset)
{
	sna->kgem.surface -=
		sizeof(struct gen5_surface_state_padded) / sizeof(uint32_t);

	DBG(("%s(%x)\n", __FUNCTION__, 4*sna->kgem.surface));

	/* Clear all surplus entries to zero in case of prefetch */
	*offset = sna->kgem.surface;
	return memset(sna->kgem.batch + sna->kgem.surface,
		      0, sizeof(struct gen5_surface_state_padded));
}

static void
gen5_emit_urb(struct sna *sna)
{
	int urb_vs_start, urb_vs_size;
	int urb_gs_start, urb_gs_size;
	int urb_clip_start, urb_clip_size;
	int urb_sf_start, urb_sf_size;
	int urb_cs_start, urb_cs_size;

	urb_vs_start = 0;
	urb_vs_size = URB_VS_ENTRIES * URB_VS_ENTRY_SIZE;
	urb_gs_start = urb_vs_start + urb_vs_size;
	urb_gs_size = URB_GS_ENTRIES * URB_GS_ENTRY_SIZE;
	urb_clip_start = urb_gs_start + urb_gs_size;
	urb_clip_size = URB_CLIP_ENTRIES * URB_CLIP_ENTRY_SIZE;
	urb_sf_start = urb_clip_start + urb_clip_size;
	urb_sf_size = URB_SF_ENTRIES * URB_SF_ENTRY_SIZE;
	urb_cs_start = urb_sf_start + urb_sf_size;
	urb_cs_size = URB_CS_ENTRIES * URB_CS_ENTRY_SIZE;

	OUT_BATCH(GEN5_URB_FENCE |
		  UF0_CS_REALLOC |
		  UF0_SF_REALLOC |
		  UF0_CLIP_REALLOC |
		  UF0_GS_REALLOC |
		  UF0_VS_REALLOC |
		  1);
	OUT_BATCH(((urb_clip_start + urb_clip_size) << UF1_CLIP_FENCE_SHIFT) |
		  ((urb_gs_start + urb_gs_size) << UF1_GS_FENCE_SHIFT) |
		  ((urb_vs_start + urb_vs_size) << UF1_VS_FENCE_SHIFT));
	OUT_BATCH(((urb_cs_start + urb_cs_size) << UF2_CS_FENCE_SHIFT) |
		  ((urb_sf_start + urb_sf_size) << UF2_SF_FENCE_SHIFT));

	/* Constant buffer state */
	OUT_BATCH(GEN5_CS_URB_STATE | 0);
	OUT_BATCH((URB_CS_ENTRY_SIZE - 1) << 4 | URB_CS_ENTRIES << 0);
}

static void
gen5_emit_state_base_address(struct sna *sna)
{
	assert(sna->render_state.gen5.general_bo->proxy == NULL);
	OUT_BATCH(GEN5_STATE_BASE_ADDRESS | 6);
	OUT_BATCH(kgem_add_reloc(&sna->kgem, /* general */
				 sna->kgem.nbatch,
				 sna->render_state.gen5.general_bo,
				 I915_GEM_DOMAIN_INSTRUCTION << 16,
				 BASE_ADDRESS_MODIFY));
	OUT_BATCH(kgem_add_reloc(&sna->kgem, /* surface */
				 sna->kgem.nbatch,
				 NULL,
				 I915_GEM_DOMAIN_INSTRUCTION << 16,
				 BASE_ADDRESS_MODIFY));
	OUT_BATCH(0); /* media */
	OUT_BATCH(kgem_add_reloc(&sna->kgem, /* instruction */
				 sna->kgem.nbatch,
				 sna->render_state.gen5.general_bo,
				 I915_GEM_DOMAIN_INSTRUCTION << 16,
				 BASE_ADDRESS_MODIFY));

	/* upper bounds, all disabled */
	OUT_BATCH(BASE_ADDRESS_MODIFY);
	OUT_BATCH(0);
	OUT_BATCH(BASE_ADDRESS_MODIFY);
}

static void
gen5_emit_invariant(struct sna *sna)
{
	/* Ironlake errata workaround: Before disabling the clipper,
	 * you have to MI_FLUSH to get the pipeline idle.
	 *
	 * However, the kernel flushes the pipeline between batches,
	 * so we should be safe....
	 * OUT_BATCH(MI_FLUSH | MI_INHIBIT_RENDER_CACHE_FLUSH);
	 */
	OUT_BATCH(GEN5_PIPELINE_SELECT | PIPELINE_SELECT_3D);

	gen5_emit_state_base_address(sna);

	sna->render_state.gen5.needs_invariant = false;
}

static void
gen5_get_batch(struct sna *sna, const struct sna_composite_op *op)
{
	kgem_set_mode(&sna->kgem, KGEM_RENDER, op->dst.bo);

	if (!kgem_check_batch_with_surfaces(&sna->kgem, 150, 4)) {
		DBG(("%s: flushing batch: %d < %d+%d\n",
		     __FUNCTION__, sna->kgem.surface - sna->kgem.nbatch,
		     150, 4*8));
		kgem_submit(&sna->kgem);
		_kgem_set_mode(&sna->kgem, KGEM_RENDER);
	}

	if (sna->render_state.gen5.needs_invariant)
		gen5_emit_invariant(sna);
}

static void
gen5_align_vertex(struct sna *sna, const struct sna_composite_op *op)
{
	assert(op->floats_per_rect == 3*op->floats_per_vertex);
	if (op->floats_per_vertex != sna->render_state.gen5.floats_per_vertex) {
		if (sna->render.vertex_size - sna->render.vertex_used < 2*op->floats_per_rect)
			gen4_vertex_finish(sna);

		DBG(("aligning vertex: was %d, now %d floats per vertex, %d->%d\n",
		     sna->render_state.gen5.floats_per_vertex,
		     op->floats_per_vertex,
		     sna->render.vertex_index,
		     (sna->render.vertex_used + op->floats_per_vertex - 1) / op->floats_per_vertex));
		sna->render.vertex_index = (sna->render.vertex_used + op->floats_per_vertex - 1) / op->floats_per_vertex;
		sna->render.vertex_used = sna->render.vertex_index * op->floats_per_vertex;
		sna->render_state.gen5.floats_per_vertex = op->floats_per_vertex;
	}
}

static void
gen5_emit_binding_table(struct sna *sna, uint16_t offset)
{
	if (!DBG_NO_STATE_CACHE &&
	    sna->render_state.gen5.surface_table == offset)
		return;

	sna->render_state.gen5.surface_table = offset;

	/* Binding table pointers */
	OUT_BATCH(GEN5_3DSTATE_BINDING_TABLE_POINTERS | 4);
	OUT_BATCH(0);		/* vs */
	OUT_BATCH(0);		/* gs */
	OUT_BATCH(0);		/* clip */
	OUT_BATCH(0);		/* sf */
	/* Only the PS uses the binding table */
	OUT_BATCH(offset*4);
}

static bool
gen5_emit_pipelined_pointers(struct sna *sna,
			     const struct sna_composite_op *op,
			     int blend, int kernel)
{
	uint16_t sp, bp;
	uint32_t key;

	DBG(("%s: has_mask=%d, src=(%d, %d), mask=(%d, %d),kernel=%d, blend=%d, ca=%d, format=%x\n",
	     __FUNCTION__, op->u.gen5.ve_id & 2,
	     op->src.filter, op->src.repeat,
	     op->mask.filter, op->mask.repeat,
	     kernel, blend, op->has_component_alpha, (int)op->dst.format));

	sp = SAMPLER_OFFSET(op->src.filter, op->src.repeat,
			    op->mask.filter, op->mask.repeat,
			    kernel);
	bp = gen5_get_blend(blend, op->has_component_alpha, op->dst.format);

	DBG(("%s: sp=%d, bp=%d\n", __FUNCTION__, sp, bp));
	key = sp | (uint32_t)bp << 16 | (op->mask.bo != NULL) << 31;
	if (key == sna->render_state.gen5.last_pipelined_pointers)
		return false;


	OUT_BATCH(GEN5_3DSTATE_PIPELINED_POINTERS | 5);
	OUT_BATCH(sna->render_state.gen5.vs);
	OUT_BATCH(GEN5_GS_DISABLE); /* passthrough */
	OUT_BATCH(GEN5_CLIP_DISABLE); /* passthrough */
	OUT_BATCH(sna->render_state.gen5.sf[op->mask.bo != NULL]);
	OUT_BATCH(sna->render_state.gen5.wm + sp);
	OUT_BATCH(sna->render_state.gen5.cc + bp);

	sna->render_state.gen5.last_pipelined_pointers = key;
	return true;
}

static void
gen5_emit_drawing_rectangle(struct sna *sna, const struct sna_composite_op *op)
{
	uint32_t limit = (op->dst.height - 1) << 16 | (op->dst.width - 1);
	uint32_t offset = (uint16_t)op->dst.y << 16 | (uint16_t)op->dst.x;

	assert(!too_large(op->dst.x, op->dst.y));
	assert(!too_large(op->dst.width, op->dst.height));

	if (!DBG_NO_STATE_CACHE &&
	    sna->render_state.gen5.drawrect_limit == limit &&
	    sna->render_state.gen5.drawrect_offset == offset)
		return;

	sna->render_state.gen5.drawrect_offset = offset;
	sna->render_state.gen5.drawrect_limit = limit;

	OUT_BATCH(GEN5_3DSTATE_DRAWING_RECTANGLE | (4 - 2));
	OUT_BATCH(0x00000000);
	OUT_BATCH(limit);
	OUT_BATCH(offset);
}

static void
gen5_emit_vertex_elements(struct sna *sna,
			  const struct sna_composite_op *op)
{
	/*
	 * vertex data in vertex buffer
	 *    position: (x, y)
	 *    texture coordinate 0: (u0, v0) if (is_affine is true) else (u0, v0, w0)
	 *    texture coordinate 1 if (has_mask is true): same as above
	 */
	struct gen5_render_state *render = &sna->render_state.gen5;
	int id = op->u.gen5.ve_id;
	bool has_mask = id >> 2;
	uint32_t format, dw;

	if (!DBG_NO_STATE_CACHE && render->ve_id == id)
		return;

	DBG(("%s: changing %d -> %d\n", __FUNCTION__, render->ve_id, id));
	render->ve_id = id;

	/* The VUE layout
	 *    dword 0-3: pad (0.0, 0.0, 0.0. 0.0)
	 *    dword 4-7: position (x, y, 1.0, 1.0),
	 *    dword 8-11: texture coordinate 0 (u0, v0, w0, 1.0)
	 *    dword 12-15: texture coordinate 1 (u1, v1, w1, 1.0)
	 *
	 * dword 4-15 are fetched from vertex buffer
	 */
	OUT_BATCH(GEN5_3DSTATE_VERTEX_ELEMENTS |
		((2 * (has_mask ? 4 : 3)) + 1 - 2));

	OUT_BATCH((id << VE0_VERTEX_BUFFER_INDEX_SHIFT) | VE0_VALID |
		  (GEN5_SURFACEFORMAT_R32G32B32A32_FLOAT << VE0_FORMAT_SHIFT) |
		  (0 << VE0_OFFSET_SHIFT));
	OUT_BATCH((VFCOMPONENT_STORE_0 << VE1_VFCOMPONENT_0_SHIFT) |
		  (VFCOMPONENT_STORE_0 << VE1_VFCOMPONENT_1_SHIFT) |
		  (VFCOMPONENT_STORE_0 << VE1_VFCOMPONENT_2_SHIFT) |
		  (VFCOMPONENT_STORE_0 << VE1_VFCOMPONENT_3_SHIFT));

	/* x,y */
	OUT_BATCH(id << VE0_VERTEX_BUFFER_INDEX_SHIFT | VE0_VALID |
		  GEN5_SURFACEFORMAT_R16G16_SSCALED << VE0_FORMAT_SHIFT |
		  0 << VE0_OFFSET_SHIFT);
	OUT_BATCH(VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_0_SHIFT |
		  VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_1_SHIFT |
		  VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_2_SHIFT |
		  VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_3_SHIFT);

	/* u0, v0, w0 */
	DBG(("%s: id=%d, first channel %d floats, offset=4b\n", __FUNCTION__,
	     id, id & 3));
	dw = VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_3_SHIFT;
	switch (id & 3) {
	default:
		assert(0);
	case 0:
		format = GEN5_SURFACEFORMAT_R16G16_SSCALED << VE0_FORMAT_SHIFT;
		dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_0_SHIFT;
		dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_1_SHIFT;
		dw |= VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_2_SHIFT;
		break;
	case 1:
		format = GEN5_SURFACEFORMAT_R32_FLOAT << VE0_FORMAT_SHIFT;
		dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_0_SHIFT;
		dw |= VFCOMPONENT_STORE_0 << VE1_VFCOMPONENT_1_SHIFT;
		dw |= VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_2_SHIFT;
		break;
	case 2:
		format = GEN5_SURFACEFORMAT_R32G32_FLOAT << VE0_FORMAT_SHIFT;
		dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_0_SHIFT;
		dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_1_SHIFT;
		dw |= VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_2_SHIFT;
		break;
	case 3:
		format = GEN5_SURFACEFORMAT_R32G32B32_FLOAT << VE0_FORMAT_SHIFT;
		dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_0_SHIFT;
		dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_1_SHIFT;
		dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_2_SHIFT;
		break;
	}
	OUT_BATCH(id << VE0_VERTEX_BUFFER_INDEX_SHIFT | VE0_VALID |
		  format | 4 << VE0_OFFSET_SHIFT);
	OUT_BATCH(dw);

	/* u1, v1, w1 */
	if (has_mask) {
		unsigned offset = 4 + ((id & 3) ?: 1) * sizeof(float);
		DBG(("%s: id=%x, second channel %d floats, offset=%db\n", __FUNCTION__,
		     id, id >> 2, offset));
		dw = VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_3_SHIFT;
		switch (id >> 2) {
		case 1:
			format = GEN5_SURFACEFORMAT_R32_FLOAT << VE0_FORMAT_SHIFT;
			dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_0_SHIFT;
			dw |= VFCOMPONENT_STORE_0 << VE1_VFCOMPONENT_1_SHIFT;
			dw |= VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_2_SHIFT;
			break;
		default:
			assert(0);
		case 2:
			format = GEN5_SURFACEFORMAT_R32G32_FLOAT << VE0_FORMAT_SHIFT;
			dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_0_SHIFT;
			dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_1_SHIFT;
			dw |= VFCOMPONENT_STORE_1_FLT << VE1_VFCOMPONENT_2_SHIFT;
			break;
		case 3:
			format = GEN5_SURFACEFORMAT_R32G32B32_FLOAT << VE0_FORMAT_SHIFT;
			dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_0_SHIFT;
			dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_1_SHIFT;
			dw |= VFCOMPONENT_STORE_SRC << VE1_VFCOMPONENT_2_SHIFT;
			break;
		}
		OUT_BATCH(id << VE0_VERTEX_BUFFER_INDEX_SHIFT | VE0_VALID |
			  format | offset << VE0_OFFSET_SHIFT);
		OUT_BATCH(dw);
	}
}

static void
gen5_emit_state(struct sna *sna,
		const struct sna_composite_op *op,
		uint16_t offset)
{
	if (kgem_bo_is_dirty(op->src.bo) || kgem_bo_is_dirty(op->mask.bo)) {
		DBG(("%s: flushing dirty (%d, %d)\n", __FUNCTION__,
		     kgem_bo_is_dirty(op->src.bo),
		     kgem_bo_is_dirty(op->mask.bo)));
		OUT_BATCH(MI_FLUSH);
		kgem_clear_dirty(&sna->kgem);
		kgem_bo_mark_dirty(op->dst.bo);
	}

	/* drawrect must be first for Ironlake BLT workaround */
	gen5_emit_drawing_rectangle(sna, op);
	gen5_emit_binding_table(sna, offset);
	if (gen5_emit_pipelined_pointers(sna, op, op->op, op->u.gen5.wm_kernel))
		gen5_emit_urb(sna);
	gen5_emit_vertex_elements(sna, op);
}

static void gen5_bind_surfaces(struct sna *sna,
			       const struct sna_composite_op *op)
{
	uint32_t *binding_table;
	uint16_t offset;

	gen5_get_batch(sna, op);

	binding_table = gen5_composite_get_binding_table(sna, &offset);

	binding_table[0] =
		gen5_bind_bo(sna,
			    op->dst.bo, op->dst.width, op->dst.height,
			    gen5_get_dest_format(op->dst.format),
			    true);
	binding_table[1] =
		gen5_bind_bo(sna,
			     op->src.bo, op->src.width, op->src.height,
			     op->src.card_format,
			     false);
	if (op->mask.bo) {
		assert(op->u.gen5.ve_id >> 2);
		binding_table[2] =
			gen5_bind_bo(sna,
				     op->mask.bo,
				     op->mask.width,
				     op->mask.height,
				     op->mask.card_format,
				     false);
	}

	if (sna->kgem.surface == offset &&
	    *(uint64_t *)(sna->kgem.batch + sna->render_state.gen5.surface_table) == *(uint64_t*)binding_table &&
	    (op->mask.bo == NULL ||
	     sna->kgem.batch[sna->render_state.gen5.surface_table+2] == binding_table[2])) {
		sna->kgem.surface += sizeof(struct gen5_surface_state_padded) / sizeof(uint32_t);
		offset = sna->render_state.gen5.surface_table;
	}

	gen5_emit_state(sna, op, offset);
}

fastcall static void
gen5_render_composite_blt(struct sna *sna,
			  const struct sna_composite_op *op,
			  const struct sna_composite_rectangles *r)
{
	DBG(("%s: src=(%d, %d)+(%d, %d), mask=(%d, %d)+(%d, %d), dst=(%d, %d)+(%d, %d), size=(%d, %d)\n",
	     __FUNCTION__,
	     r->src.x, r->src.y, op->src.offset[0], op->src.offset[1],
	     r->mask.x, r->mask.y, op->mask.offset[0], op->mask.offset[1],
	     r->dst.x, r->dst.y, op->dst.x, op->dst.y,
	     r->width, r->height));

	gen5_get_rectangles(sna, op, 1, gen5_bind_surfaces);
	op->prim_emit(sna, op, r);
}


static void
gen5_render_composite_done(struct sna *sna,
			   const struct sna_composite_op *op)
{
	if (sna->render.vertex_offset) {
		gen4_vertex_flush(sna);
		gen5_magic_ca_pass(sna,op);
	}

	DBG(("%s()\n", __FUNCTION__));

}


static bool
gen5_blit_tex(struct sna *sna,
              uint8_t op,
		      PixmapPtr src, struct kgem_bo *src_bo,
		      PixmapPtr mask,struct kgem_bo *mask_bo,
		      PixmapPtr dst, struct kgem_bo *dst_bo, 
              int32_t src_x, int32_t src_y,
              int32_t msk_x, int32_t msk_y,
              int32_t dst_x, int32_t dst_y,
              int32_t width, int32_t height,
              struct sna_composite_op *tmp)
{
	DBG(("%s: %dx%d, current mode=%d\n", __FUNCTION__,
	     width, height, sna->kgem.mode));

    tmp->op = PictOpSrc;

    tmp->dst.pixmap = dst;
    tmp->dst.bo     = dst_bo;
    tmp->dst.width  = dst->drawable.width;
    tmp->dst.height = dst->drawable.height;
    tmp->dst.format = PICT_x8r8g8b8;


	tmp->src.repeat = RepeatNone;
	tmp->src.filter = PictFilterNearest;
    tmp->src.is_affine = true;

    tmp->src.bo = src_bo;
	tmp->src.pict_format = PICT_x8r8g8b8;
    tmp->src.card_format = gen5_get_card_format(tmp->src.pict_format);
    tmp->src.width  = src->drawable.width;
    tmp->src.height = src->drawable.height;


    tmp->is_affine = tmp->src.is_affine;
	tmp->has_component_alpha = false;
	tmp->need_magic_ca_pass = false;
	
    tmp->mask.is_affine = true;
 	tmp->mask.repeat = SAMPLER_EXTEND_NONE;
	tmp->mask.filter = SAMPLER_FILTER_NEAREST;
    tmp->mask.bo = mask_bo;
    tmp->mask.pict_format = PIXMAN_a8;
    tmp->mask.card_format = gen5_get_card_format(tmp->mask.pict_format);
    tmp->mask.width  = mask->drawable.width;
    tmp->mask.height = mask->drawable.height;

    tmp->src.scale[0] = 1.f/width;            //src->width;
    tmp->src.scale[1] = 1.f/height;            //src->height;

    tmp->mask.scale[0] = 1.f/mask->drawable.width;
    tmp->mask.scale[1] = 1.f/mask->drawable.height;
	
	
	tmp->u.gen5.wm_kernel =
		gen5_choose_composite_kernel(tmp->op,
					     tmp->mask.bo != NULL,
					     tmp->has_component_alpha,
					     tmp->is_affine);
	tmp->u.gen5.ve_id = gen4_choose_composite_emitter(tmp);

	tmp->blt   = gen5_render_composite_blt;
//	tmp->box   = gen5_render_composite_box;
	tmp->done  = gen5_render_composite_done;

	if (!kgem_check_bo(&sna->kgem,
			   tmp->dst.bo, tmp->src.bo, tmp->mask.bo, NULL)) {
		kgem_submit(&sna->kgem);
	}

	gen5_bind_surfaces(sna, tmp);
	gen5_align_vertex(sna, tmp);
	return true;

	return false;
}



static void
gen5_render_flush(struct sna *sna)
{
	gen4_vertex_close(sna);

	assert(sna->render.vb_id == 0);
	assert(sna->render.vertex_offset == 0);
}

static void
gen5_render_context_switch(struct kgem *kgem,
			   int new_mode)
{
	if (!kgem->nbatch)
		return;

	/* WaNonPipelinedStateCommandFlush
	 *
	 * Ironlake has a limitation that a 3D or Media command can't
	 * be the first command after a BLT, unless it's
	 * non-pipelined.
	 *
	 * We do this by ensuring that the non-pipelined drawrect
	 * is always emitted first following a switch from BLT.
	 */
	if (kgem->mode == KGEM_BLT) {
		struct sna *sna = to_sna_from_kgem(kgem);
		DBG(("%s: forcing drawrect on next state emission\n",
		     __FUNCTION__));
		sna->render_state.gen5.drawrect_limit = -1;
	}

	if (kgem_ring_is_idle(kgem, kgem->ring)) {
		DBG(("%s: GPU idle, flushing\n", __FUNCTION__));
		_kgem_submit(kgem);
	}
}

static void
discard_vbo(struct sna *sna)
{
	kgem_bo_destroy(&sna->kgem, sna->render.vbo);
	sna->render.vbo = NULL;
	sna->render.vertices = sna->render.vertex_data;
	sna->render.vertex_size = ARRAY_SIZE(sna->render.vertex_data);
	sna->render.vertex_used = 0;
	sna->render.vertex_index = 0;
}

static void
gen5_render_retire(struct kgem *kgem)
{
	struct sna *sna;

	sna = container_of(kgem, struct sna, kgem);
	if (kgem->nbatch == 0 && sna->render.vbo && !kgem_bo_is_busy(sna->render.vbo)) {
		DBG(("%s: resetting idle vbo\n", __FUNCTION__));
		sna->render.vertex_used = 0;
		sna->render.vertex_index = 0;
	}
}

static void
gen5_render_expire(struct kgem *kgem)
{
	struct sna *sna;

	sna = container_of(kgem, struct sna, kgem);
	if (sna->render.vbo && !sna->render.vertex_used) {
		DBG(("%s: discarding vbo\n", __FUNCTION__));
		discard_vbo(sna);
	}
}

static void gen5_render_reset(struct sna *sna)
{
	sna->render_state.gen5.needs_invariant = true;
	sna->render_state.gen5.ve_id = -1;
	sna->render_state.gen5.last_primitive = -1;
	sna->render_state.gen5.last_pipelined_pointers = 0;

	sna->render_state.gen5.drawrect_offset = -1;
	sna->render_state.gen5.drawrect_limit = -1;
	sna->render_state.gen5.surface_table = -1;

	if (sna->render.vbo &&
	    !kgem_bo_is_mappable(&sna->kgem, sna->render.vbo)) {
		DBG(("%s: discarding unmappable vbo\n", __FUNCTION__));
		discard_vbo(sna);
	}

	sna->render.vertex_offset = 0;
	sna->render.nvertex_reloc = 0;
	sna->render.vb_id = 0;
}

static void gen5_render_fini(struct sna *sna)
{
	kgem_bo_destroy(&sna->kgem, sna->render_state.gen5.general_bo);
}

static uint32_t gen5_create_vs_unit_state(struct sna_static_stream *stream)
{
	struct gen5_vs_unit_state *vs = sna_static_stream_map(stream, sizeof(*vs), 32);

	/* Set up the vertex shader to be disabled (passthrough) */
	vs->thread4.nr_urb_entries = URB_VS_ENTRIES >> 2;
	vs->thread4.urb_entry_allocation_size = URB_VS_ENTRY_SIZE - 1;
	vs->vs6.vs_enable = 0;
	vs->vs6.vert_cache_disable = 1;

	return sna_static_stream_offsetof(stream, vs);
}

static uint32_t gen5_create_sf_state(struct sna_static_stream *stream,
				     uint32_t kernel)
{
	struct gen5_sf_unit_state *sf_state;

	sf_state = sna_static_stream_map(stream, sizeof(*sf_state), 32);

	sf_state->thread0.grf_reg_count = GEN5_GRF_BLOCKS(SF_KERNEL_NUM_GRF);
	sf_state->thread0.kernel_start_pointer = kernel >> 6;

	sf_state->thread3.const_urb_entry_read_length = 0;	/* no const URBs */
	sf_state->thread3.const_urb_entry_read_offset = 0;	/* no const URBs */
	sf_state->thread3.urb_entry_read_length = 1;	/* 1 URB per vertex */
	/* don't smash vertex header, read start from dw8 */
	sf_state->thread3.urb_entry_read_offset = 1;
	sf_state->thread3.dispatch_grf_start_reg = 3;
	sf_state->thread4.max_threads = SF_MAX_THREADS - 1;
	sf_state->thread4.urb_entry_allocation_size = URB_SF_ENTRY_SIZE - 1;
	sf_state->thread4.nr_urb_entries = URB_SF_ENTRIES;
	sf_state->sf5.viewport_transform = false;	/* skip viewport */
	sf_state->sf6.cull_mode = GEN5_CULLMODE_NONE;
	sf_state->sf6.scissor = 0;
	sf_state->sf7.trifan_pv = 2;
	sf_state->sf6.dest_org_vbias = 0x8;
	sf_state->sf6.dest_org_hbias = 0x8;

	return sna_static_stream_offsetof(stream, sf_state);
}

static uint32_t gen5_create_sampler_state(struct sna_static_stream *stream,
					  sampler_filter_t src_filter,
					  sampler_extend_t src_extend,
					  sampler_filter_t mask_filter,
					  sampler_extend_t mask_extend)
{
	struct gen5_sampler_state *sampler_state;

	sampler_state = sna_static_stream_map(stream,
					      sizeof(struct gen5_sampler_state) * 2,
					      32);
	sampler_state_init(&sampler_state[0], src_filter, src_extend);
	sampler_state_init(&sampler_state[1], mask_filter, mask_extend);

	return sna_static_stream_offsetof(stream, sampler_state);
}

static void gen5_init_wm_state(struct gen5_wm_unit_state *state,
			       bool has_mask,
			       uint32_t kernel,
			       uint32_t sampler)
{
	state->thread0.grf_reg_count = GEN5_GRF_BLOCKS(PS_KERNEL_NUM_GRF);
	state->thread0.kernel_start_pointer = kernel >> 6;

	state->thread1.single_program_flow = 0;

	/* scratch space is not used in our kernel */
	state->thread2.scratch_space_base_pointer = 0;
	state->thread2.per_thread_scratch_space = 0;

	state->thread3.const_urb_entry_read_length = 0;
	state->thread3.const_urb_entry_read_offset = 0;

	state->thread3.urb_entry_read_offset = 0;
	/* wm kernel use urb from 3, see wm_program in compiler module */
	state->thread3.dispatch_grf_start_reg = 3;	/* must match kernel */

	state->wm4.sampler_count = 0;	/* hardware requirement */

	state->wm4.sampler_state_pointer = sampler >> 5;
	state->wm5.max_threads = PS_MAX_THREADS - 1;
	state->wm5.transposed_urb_read = 0;
	state->wm5.thread_dispatch_enable = 1;
	/* just use 16-pixel dispatch (4 subspans), don't need to change kernel
	 * start point
	 */
	state->wm5.enable_16_pix = 1;
	state->wm5.enable_8_pix = 0;
	state->wm5.early_depth_test = 1;

	/* Each pair of attributes (src/mask coords) is two URB entries */
	if (has_mask) {
		state->thread1.binding_table_entry_count = 3;	/* 2 tex and fb */
		state->thread3.urb_entry_read_length = 4;
	} else {
		state->thread1.binding_table_entry_count = 2;	/* 1 tex and fb */
		state->thread3.urb_entry_read_length = 2;
	}

	/* binding table entry count is only used for prefetching,
	 * and it has to be set 0 for Ironlake
	 */
	state->thread1.binding_table_entry_count = 0;
}

static uint32_t gen5_create_cc_unit_state(struct sna_static_stream *stream)
{
	uint8_t *ptr, *base;
	int i, j;

	base = ptr =
		sna_static_stream_map(stream,
				      GEN5_BLENDFACTOR_COUNT*GEN5_BLENDFACTOR_COUNT*64,
				      64);

	for (i = 0; i < GEN5_BLENDFACTOR_COUNT; i++) {
		for (j = 0; j < GEN5_BLENDFACTOR_COUNT; j++) {
			struct gen5_cc_unit_state *state =
				(struct gen5_cc_unit_state *)ptr;

			state->cc3.blend_enable =
				!(j == GEN5_BLENDFACTOR_ZERO && i == GEN5_BLENDFACTOR_ONE);

			state->cc5.logicop_func = 0xc;	/* COPY */
			state->cc5.ia_blend_function = GEN5_BLENDFUNCTION_ADD;

			/* Fill in alpha blend factors same as color, for the future. */
			state->cc5.ia_src_blend_factor = i;
			state->cc5.ia_dest_blend_factor = j;

			state->cc6.blend_function = GEN5_BLENDFUNCTION_ADD;
			state->cc6.clamp_post_alpha_blend = 1;
			state->cc6.clamp_pre_alpha_blend = 1;
			state->cc6.src_blend_factor = i;
			state->cc6.dest_blend_factor = j;

			ptr += 64;
		}
	}

	return sna_static_stream_offsetof(stream, base);
}

static bool gen5_render_setup(struct sna *sna)
{
	struct gen5_render_state *state = &sna->render_state.gen5;
	struct sna_static_stream general;
	struct gen5_wm_unit_state_padded *wm_state;
	uint32_t sf[2], wm[KERNEL_COUNT];
	int i, j, k, l, m;

	sna_static_stream_init(&general);

	/* Zero pad the start. If you see an offset of 0x0 in the batchbuffer
	 * dumps, you know it points to zero.
	 */
	null_create(&general);

	/* Set up the two SF states (one for blending with a mask, one without) */
	sf[0] = sna_static_stream_compile_sf(sna, &general, brw_sf_kernel__nomask);
	sf[1] = sna_static_stream_compile_sf(sna, &general, brw_sf_kernel__mask);

	for (m = 0; m < KERNEL_COUNT; m++) {
		if (wm_kernels[m].size) {
			wm[m] = sna_static_stream_add(&general,
						      wm_kernels[m].data,
						      wm_kernels[m].size,
						      64);
		} else {
			wm[m] = sna_static_stream_compile_wm(sna, &general,
							     wm_kernels[m].data,
							     16);
		}
		assert(wm[m]);
	}

	state->vs = gen5_create_vs_unit_state(&general);

	state->sf[0] = gen5_create_sf_state(&general, sf[0]);
	state->sf[1] = gen5_create_sf_state(&general, sf[1]);


	/* Set up the WM states: each filter/extend type for source and mask, per
	 * kernel.
	 */
	wm_state = sna_static_stream_map(&general,
					  sizeof(*wm_state) * KERNEL_COUNT *
					  FILTER_COUNT * EXTEND_COUNT *
					  FILTER_COUNT * EXTEND_COUNT,
					  64);
	state->wm = sna_static_stream_offsetof(&general, wm_state);
	for (i = 0; i < FILTER_COUNT; i++) {
		for (j = 0; j < EXTEND_COUNT; j++) {
			for (k = 0; k < FILTER_COUNT; k++) {
				for (l = 0; l < EXTEND_COUNT; l++) {
					uint32_t sampler_state;

					sampler_state =
						gen5_create_sampler_state(&general,
									  i, j,
									  k, l);

					for (m = 0; m < KERNEL_COUNT; m++) {
						gen5_init_wm_state(&wm_state->state,
								   wm_kernels[m].has_mask,
								   wm[m], sampler_state);
						wm_state++;
					}
				}
        }
        }
    }

    state->cc = gen5_create_cc_unit_state(&general);

    state->general_bo = sna_static_stream_fini(sna, &general);
    return state->general_bo != NULL;
}

bool gen5_render_init(struct sna *sna)
{
	if (!gen5_render_setup(sna))
		return false;

	sna->kgem.context_switch = gen5_render_context_switch;
	sna->kgem.retire = gen5_render_retire;
	sna->kgem.expire = gen5_render_expire;

    sna->render.blit_tex = gen5_blit_tex;

	sna->render.flush = gen5_render_flush;
	sna->render.reset = gen5_render_reset;
	sna->render.fini = gen5_render_fini;

	sna->render.max_3d_size = MAX_3D_SIZE;
	sna->render.max_3d_pitch = 1 << 18;
	return true;
}