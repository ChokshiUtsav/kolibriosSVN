/*
 * Copyright 2008 Advanced Micro Devices, Inc.
 * Copyright 2008 Red Hat Inc.
 * Copyright 2009 Jerome Glisse.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Dave Airlie
 *          Alex Deucher
 *          Jerome Glisse
 */
//#include <linux/console.h>

#include <drm/drmP.h>
#include <drm/drm_crtc_helper.h>
#include <drm/radeon_drm.h>
#include "radeon_reg.h"
#include "radeon.h"
#include "radeon_asic.h"
#include "atom.h"
#include "display.h"

#include <drm/drm_pciids.h>


int radeon_no_wb;
int radeon_modeset = -1;
int radeon_dynclks = -1;
int radeon_r4xx_atom = 0;
int radeon_agpmode = 0;
int radeon_vram_limit = 0;
int radeon_gart_size = 512; /* default gart size */
int radeon_benchmarking = 0;
int radeon_testing = 0;
int radeon_connector_table = 0;
int radeon_tv = 1;
int radeon_new_pll = -1;
int radeon_dynpm = -1;
int radeon_audio = 1;


extern display_t *rdisplay;

void parse_cmdline(char *cmdline, videomode_t *mode, char *log, int *kms);
int init_display(struct radeon_device *rdev, videomode_t *mode);
int init_display_kms(struct radeon_device *rdev, videomode_t *mode);

int get_modes(videomode_t *mode, int *count);
int set_user_mode(videomode_t *mode);
int r100_2D_test(struct radeon_device *rdev);


 /* Legacy VGA regions */
#define VGA_RSRC_NONE          0x00
#define VGA_RSRC_LEGACY_IO     0x01
#define VGA_RSRC_LEGACY_MEM    0x02
#define VGA_RSRC_LEGACY_MASK   (VGA_RSRC_LEGACY_IO | VGA_RSRC_LEGACY_MEM)
/* Non-legacy access */
#define VGA_RSRC_NORMAL_IO     0x04
#define VGA_RSRC_NORMAL_MEM    0x08



/*
 * Clear GPU surface registers.
 */
void radeon_surface_init(struct radeon_device *rdev)
{
    /* FIXME: check this out */
    if (rdev->family < CHIP_R600) {
        int i;

		for (i = 0; i < RADEON_GEM_MAX_SURFACES; i++) {
           radeon_clear_surface_reg(rdev, i);
        }
		/* enable surfaces */
		WREG32(RADEON_SURFACE_CNTL, 0);
    }
}

/*
 * GPU scratch registers helpers function.
 */
void radeon_scratch_init(struct radeon_device *rdev)
{
    int i;

    /* FIXME: check this out */
    if (rdev->family < CHIP_R300) {
        rdev->scratch.num_reg = 5;
    } else {
        rdev->scratch.num_reg = 7;
    }
    for (i = 0; i < rdev->scratch.num_reg; i++) {
        rdev->scratch.free[i] = true;
        rdev->scratch.reg[i] = RADEON_SCRATCH_REG0 + (i * 4);
    }
}

int radeon_scratch_get(struct radeon_device *rdev, uint32_t *reg)
{
	int i;

	for (i = 0; i < rdev->scratch.num_reg; i++) {
		if (rdev->scratch.free[i]) {
			rdev->scratch.free[i] = false;
			*reg = rdev->scratch.reg[i];
			return 0;
		}
	}
	return -EINVAL;
}

void radeon_scratch_free(struct radeon_device *rdev, uint32_t reg)
{
	int i;

	for (i = 0; i < rdev->scratch.num_reg; i++) {
		if (rdev->scratch.reg[i] == reg) {
			rdev->scratch.free[i] = true;
			return;
		}
	}
}

/**
 * radeon_vram_location - try to find VRAM location
 * @rdev: radeon device structure holding all necessary informations
 * @mc: memory controller structure holding memory informations
 * @base: base address at which to put VRAM
 *
 * Function will place try to place VRAM at base address provided
 * as parameter (which is so far either PCI aperture address or
 * for IGP TOM base address).
 *
 * If there is not enough space to fit the unvisible VRAM in the 32bits
 * address space then we limit the VRAM size to the aperture.
 *
 * If we are using AGP and if the AGP aperture doesn't allow us to have
 * room for all the VRAM than we restrict the VRAM to the PCI aperture
 * size and print a warning.
 *
 * This function will never fails, worst case are limiting VRAM.
 *
 * Note: GTT start, end, size should be initialized before calling this
 * function on AGP platform.
 *
 * Note: We don't explictly enforce VRAM start to be aligned on VRAM size,
 * this shouldn't be a problem as we are using the PCI aperture as a reference.
 * Otherwise this would be needed for rv280, all r3xx, and all r4xx, but
 * not IGP.
 *
 * Note: we use mc_vram_size as on some board we need to program the mc to
 * cover the whole aperture even if VRAM size is inferior to aperture size
 * Novell bug 204882 + along with lots of ubuntu ones
 *
 * Note: when limiting vram it's safe to overwritte real_vram_size because
 * we are not in case where real_vram_size is inferior to mc_vram_size (ie
 * note afected by bogus hw of Novell bug 204882 + along with lots of ubuntu
 * ones)
 *
 * Note: IGP TOM addr should be the same as the aperture addr, we don't
 * explicitly check for that thought.
 *
 * FIXME: when reducing VRAM size align new size on power of 2.
 */
void radeon_vram_location(struct radeon_device *rdev, struct radeon_mc *mc, u64 base)
{
	mc->vram_start = base;
	if (mc->mc_vram_size > (0xFFFFFFFF - base + 1)) {
		dev_warn(rdev->dev, "limiting VRAM to PCI aperture size\n");
		mc->real_vram_size = mc->aper_size;
		mc->mc_vram_size = mc->aper_size;
	}
	mc->vram_end = mc->vram_start + mc->mc_vram_size - 1;
	if (rdev->flags & RADEON_IS_AGP && mc->vram_end > mc->gtt_start && mc->vram_end <= mc->gtt_end) {
		dev_warn(rdev->dev, "limiting VRAM to PCI aperture size\n");
		mc->real_vram_size = mc->aper_size;
		mc->mc_vram_size = mc->aper_size;
		}
	mc->vram_end = mc->vram_start + mc->mc_vram_size - 1;
	dev_info(rdev->dev, "VRAM: %lluM 0x%08llX - 0x%08llX (%lluM used)\n",
			mc->mc_vram_size >> 20, mc->vram_start,
			mc->vram_end, mc->real_vram_size >> 20);
}

/**
 * radeon_gtt_location - try to find GTT location
 * @rdev: radeon device structure holding all necessary informations
 * @mc: memory controller structure holding memory informations
 *
 * Function will place try to place GTT before or after VRAM.
 *
 * If GTT size is bigger than space left then we ajust GTT size.
 * Thus function will never fails.
 *
 * FIXME: when reducing GTT size align new size on power of 2.
 */
void radeon_gtt_location(struct radeon_device *rdev, struct radeon_mc *mc)
{
	u64 size_af, size_bf;

	size_af = 0xFFFFFFFF - mc->vram_end;
	size_bf = mc->vram_start;
	if (size_bf > size_af) {
		if (mc->gtt_size > size_bf) {
			dev_warn(rdev->dev, "limiting GTT\n");
			mc->gtt_size = size_bf;
		}
		mc->gtt_start = mc->vram_start - mc->gtt_size;
	} else {
		if (mc->gtt_size > size_af) {
			dev_warn(rdev->dev, "limiting GTT\n");
			mc->gtt_size = size_af;
		}
		mc->gtt_start = mc->vram_end + 1;
	}
	mc->gtt_end = mc->gtt_start + mc->gtt_size - 1;
	dev_info(rdev->dev, "GTT: %lluM 0x%08llX - 0x%08llX\n",
			mc->gtt_size >> 20, mc->gtt_start, mc->gtt_end);
}

/*
 * GPU helpers function.
 */
bool radeon_card_posted(struct radeon_device *rdev)
{
	uint32_t reg;

	/* first check CRTCs */
	if (ASIC_IS_DCE4(rdev)) {
		reg = RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC0_REGISTER_OFFSET) |
			RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC1_REGISTER_OFFSET) |
			RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC2_REGISTER_OFFSET) |
			RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC3_REGISTER_OFFSET) |
			RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC4_REGISTER_OFFSET) |
			RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC5_REGISTER_OFFSET);
		if (reg & EVERGREEN_CRTC_MASTER_EN)
			return true;
	} else if (ASIC_IS_AVIVO(rdev)) {
		reg = RREG32(AVIVO_D1CRTC_CONTROL) |
		      RREG32(AVIVO_D2CRTC_CONTROL);
		if (reg & AVIVO_CRTC_EN) {
			return true;
		}
	} else {
		reg = RREG32(RADEON_CRTC_GEN_CNTL) |
		      RREG32(RADEON_CRTC2_GEN_CNTL);
		if (reg & RADEON_CRTC_EN) {
			return true;
		}
	}

	/* then check MEM_SIZE, in case the crtcs are off */
	if (rdev->family >= CHIP_R600)
		reg = RREG32(R600_CONFIG_MEMSIZE);
	else
		reg = RREG32(RADEON_CONFIG_MEMSIZE);

	if (reg)
		return true;

	return false;

}

bool radeon_boot_test_post_card(struct radeon_device *rdev)
{
	if (radeon_card_posted(rdev))
		return true;

	if (rdev->bios) {
		DRM_INFO("GPU not posted. posting now...\n");
		if (rdev->is_atom_bios)
			atom_asic_init(rdev->mode_info.atom_context);
		else
			radeon_combios_asic_init(rdev->ddev);
		return true;
	} else {
		dev_err(rdev->dev, "Card not posted and no BIOS - ignoring\n");
		return false;
	}
}

int radeon_dummy_page_init(struct radeon_device *rdev)
{
	if (rdev->dummy_page.page)
		return 0;
    rdev->dummy_page.page = AllocPage();
	if (rdev->dummy_page.page == NULL)
		return -ENOMEM;
    rdev->dummy_page.addr = MapIoMem(rdev->dummy_page.page, 4096, 5);
	if (!rdev->dummy_page.addr) {
//       __free_page(rdev->dummy_page.page);
		rdev->dummy_page.page = NULL;
		return -ENOMEM;
	}
	return 0;
}

void radeon_dummy_page_fini(struct radeon_device *rdev)
{
	if (rdev->dummy_page.page == NULL)
		return;
    KernelFree(rdev->dummy_page.addr);
	rdev->dummy_page.page = NULL;
}


/*
 * Registers accessors functions.
 */
uint32_t radeon_invalid_rreg(struct radeon_device *rdev, uint32_t reg)
{
    DRM_ERROR("Invalid callback to read register 0x%04X\n", reg);
    BUG_ON(1);
    return 0;
}

void radeon_invalid_wreg(struct radeon_device *rdev, uint32_t reg, uint32_t v)
{
    DRM_ERROR("Invalid callback to write register 0x%04X with 0x%08X\n",
          reg, v);
    BUG_ON(1);
}

void radeon_register_accessor_init(struct radeon_device *rdev)
{
    rdev->mc_rreg = &radeon_invalid_rreg;
    rdev->mc_wreg = &radeon_invalid_wreg;
    rdev->pll_rreg = &radeon_invalid_rreg;
    rdev->pll_wreg = &radeon_invalid_wreg;
    rdev->pciep_rreg = &radeon_invalid_rreg;
    rdev->pciep_wreg = &radeon_invalid_wreg;

    /* Don't change order as we are overridding accessor. */
    if (rdev->family < CHIP_RV515) {
		rdev->pcie_reg_mask = 0xff;
	} else {
		rdev->pcie_reg_mask = 0x7ff;
    }
    /* FIXME: not sure here */
    if (rdev->family <= CHIP_R580) {
        rdev->pll_rreg = &r100_pll_rreg;
        rdev->pll_wreg = &r100_pll_wreg;
    }
	if (rdev->family >= CHIP_R420) {
		rdev->mc_rreg = &r420_mc_rreg;
		rdev->mc_wreg = &r420_mc_wreg;
	}
    if (rdev->family >= CHIP_RV515) {
        rdev->mc_rreg = &rv515_mc_rreg;
        rdev->mc_wreg = &rv515_mc_wreg;
    }
    if (rdev->family == CHIP_RS400 || rdev->family == CHIP_RS480) {
        rdev->mc_rreg = &rs400_mc_rreg;
        rdev->mc_wreg = &rs400_mc_wreg;
    }
    if (rdev->family == CHIP_RS690 || rdev->family == CHIP_RS740) {
        rdev->mc_rreg = &rs690_mc_rreg;
        rdev->mc_wreg = &rs690_mc_wreg;
    }
    if (rdev->family == CHIP_RS600) {
        rdev->mc_rreg = &rs600_mc_rreg;
        rdev->mc_wreg = &rs600_mc_wreg;
    }
	if ((rdev->family >= CHIP_R600) && (rdev->family <= CHIP_RV740)) {
		rdev->pciep_rreg = &r600_pciep_rreg;
		rdev->pciep_wreg = &r600_pciep_wreg;
	}
}


/*
 * ASIC
 */
int radeon_asic_init(struct radeon_device *rdev)
{
    radeon_register_accessor_init(rdev);
	switch (rdev->family) {
	case CHIP_R100:
	case CHIP_RV100:
	case CHIP_RS100:
	case CHIP_RV200:
	case CHIP_RS200:
		rdev->asic = &r100_asic;
		break;
	case CHIP_R200:
	case CHIP_RV250:
	case CHIP_RS300:
	case CHIP_RV280:
		rdev->asic = &r200_asic;
		break;
	case CHIP_R300:
	case CHIP_R350:
	case CHIP_RV350:
	case CHIP_RV380:
		if (rdev->flags & RADEON_IS_PCIE)
			rdev->asic = &r300_asic_pcie;
		else
        rdev->asic = &r300_asic;
		break;
	case CHIP_R420:
	case CHIP_R423:
	case CHIP_RV410:
        rdev->asic = &r420_asic;
		break;
	case CHIP_RS400:
	case CHIP_RS480:
       rdev->asic = &rs400_asic;
		break;
	case CHIP_RS600:
        rdev->asic = &rs600_asic;
		break;
	case CHIP_RS690:
	case CHIP_RS740:
        rdev->asic = &rs690_asic;
		break;
	case CHIP_RV515:
        rdev->asic = &rv515_asic;
		break;
	case CHIP_R520:
	case CHIP_RV530:
	case CHIP_RV560:
	case CHIP_RV570:
	case CHIP_R580:
        rdev->asic = &r520_asic;
		break;
	case CHIP_R600:
	case CHIP_RV610:
	case CHIP_RV630:
	case CHIP_RV620:
	case CHIP_RV635:
	case CHIP_RV670:
	case CHIP_RS780:
	case CHIP_RS880:
		rdev->asic = &r600_asic;
		break;
	case CHIP_RV770:
	case CHIP_RV730:
	case CHIP_RV710:
	case CHIP_RV740:
		rdev->asic = &rv770_asic;
		break;
	case CHIP_CEDAR:
	case CHIP_REDWOOD:
	case CHIP_JUNIPER:
	case CHIP_CYPRESS:
	case CHIP_HEMLOCK:
		rdev->asic = &evergreen_asic;
		break;
	default:
		/* FIXME: not supported yet */
		return -EINVAL;
	}

	if (rdev->flags & RADEON_IS_IGP) {
		rdev->asic->get_memory_clock = NULL;
		rdev->asic->set_memory_clock = NULL;
	}

	return 0;
}


/*
 * Wrapper around modesetting bits.
 */
int radeon_clocks_init(struct radeon_device *rdev)
{
	int r;

    r = radeon_static_clocks_init(rdev->ddev);
	if (r) {
		return r;
	}
	DRM_INFO("Clocks initialized !\n");
	return 0;
}

void radeon_clocks_fini(struct radeon_device *rdev)
{
}

/* ATOM accessor methods */
static uint32_t cail_pll_read(struct card_info *info, uint32_t reg)
{
    struct radeon_device *rdev = info->dev->dev_private;
    uint32_t r;

    r = rdev->pll_rreg(rdev, reg);
    return r;
}

static void cail_pll_write(struct card_info *info, uint32_t reg, uint32_t val)
{
    struct radeon_device *rdev = info->dev->dev_private;

    rdev->pll_wreg(rdev, reg, val);
}

static uint32_t cail_mc_read(struct card_info *info, uint32_t reg)
{
    struct radeon_device *rdev = info->dev->dev_private;
    uint32_t r;

    r = rdev->mc_rreg(rdev, reg);
    return r;
}

static void cail_mc_write(struct card_info *info, uint32_t reg, uint32_t val)
{
    struct radeon_device *rdev = info->dev->dev_private;

    rdev->mc_wreg(rdev, reg, val);
}

static void cail_reg_write(struct card_info *info, uint32_t reg, uint32_t val)
{
    struct radeon_device *rdev = info->dev->dev_private;

    WREG32(reg*4, val);
}

static uint32_t cail_reg_read(struct card_info *info, uint32_t reg)
{
    struct radeon_device *rdev = info->dev->dev_private;
    uint32_t r;

    r = RREG32(reg*4);
    return r;
}

int radeon_atombios_init(struct radeon_device *rdev)
{
	struct card_info *atom_card_info =
	    kzalloc(sizeof(struct card_info), GFP_KERNEL);

	if (!atom_card_info)
		return -ENOMEM;

	rdev->mode_info.atom_card_info = atom_card_info;
	atom_card_info->dev = rdev->ddev;
	atom_card_info->reg_read = cail_reg_read;
	atom_card_info->reg_write = cail_reg_write;
	atom_card_info->mc_read = cail_mc_read;
	atom_card_info->mc_write = cail_mc_write;
	atom_card_info->pll_read = cail_pll_read;
	atom_card_info->pll_write = cail_pll_write;

	rdev->mode_info.atom_context = atom_parse(atom_card_info, rdev->bios);
    radeon_atom_initialize_bios_scratch_regs(rdev->ddev);
	atom_allocate_fb_scratch(rdev->mode_info.atom_context);
    return 0;
}

void radeon_atombios_fini(struct radeon_device *rdev)
{
	if (rdev->mode_info.atom_context) {
		kfree(rdev->mode_info.atom_context->scratch);
	kfree(rdev->mode_info.atom_context);
	}
	kfree(rdev->mode_info.atom_card_info);
}

int radeon_combios_init(struct radeon_device *rdev)
{
	radeon_combios_initialize_bios_scratch_regs(rdev->ddev);
	return 0;
}

void radeon_combios_fini(struct radeon_device *rdev)
{
}

/* if we get transitioned to only one device, tak VGA back */
static unsigned int radeon_vga_set_decode(void *cookie, bool state)
{
	struct radeon_device *rdev = cookie;
	radeon_vga_set_state(rdev, state);
	if (state)
		return VGA_RSRC_LEGACY_IO | VGA_RSRC_LEGACY_MEM |
		       VGA_RSRC_NORMAL_IO | VGA_RSRC_NORMAL_MEM;
	else
		return VGA_RSRC_NORMAL_IO | VGA_RSRC_NORMAL_MEM;
}

void radeon_agp_disable(struct radeon_device *rdev)
{
	rdev->flags &= ~RADEON_IS_AGP;
	if (rdev->family >= CHIP_R600) {
		DRM_INFO("Forcing AGP to PCIE mode\n");
		rdev->flags |= RADEON_IS_PCIE;
	} else if (rdev->family >= CHIP_RV515 ||
			rdev->family == CHIP_RV380 ||
			rdev->family == CHIP_RV410 ||
			rdev->family == CHIP_R423) {
		DRM_INFO("Forcing AGP to PCIE mode\n");
		rdev->flags |= RADEON_IS_PCIE;
		rdev->asic->gart_tlb_flush = &rv370_pcie_gart_tlb_flush;
		rdev->asic->gart_set_page = &rv370_pcie_gart_set_page;
	} else {
		DRM_INFO("Forcing AGP to PCI mode\n");
		rdev->flags |= RADEON_IS_PCI;
		rdev->asic->gart_tlb_flush = &r100_pci_gart_tlb_flush;
		rdev->asic->gart_set_page = &r100_pci_gart_set_page;
	}
	rdev->mc.gtt_size = radeon_gart_size * 1024 * 1024;
}

void radeon_check_arguments(struct radeon_device *rdev)
{
	/* vramlimit must be a power of two */
	switch (radeon_vram_limit) {
	case 0:
	case 4:
	case 8:
	case 16:
	case 32:
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
	case 2048:
	case 4096:
		break;
	default:
		dev_warn(rdev->dev, "vram limit (%d) must be a power of 2\n",
				radeon_vram_limit);
		radeon_vram_limit = 0;
		break;
	}
	radeon_vram_limit = radeon_vram_limit << 20;
	/* gtt size must be power of two and greater or equal to 32M */
	switch (radeon_gart_size) {
	case 4:
	case 8:
	case 16:
		dev_warn(rdev->dev, "gart size (%d) too small forcing to 512M\n",
				radeon_gart_size);
		radeon_gart_size = 512;
		break;
	case 32:
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
	case 2048:
	case 4096:
		break;
	default:
		dev_warn(rdev->dev, "gart size (%d) must be a power of 2\n",
				radeon_gart_size);
		radeon_gart_size = 512;
		break;
	}
	rdev->mc.gtt_size = radeon_gart_size * 1024 * 1024;
	/* AGP mode can only be -1, 1, 2, 4, 8 */
	switch (radeon_agpmode) {
	case -1:
	case 0:
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		dev_warn(rdev->dev, "invalid AGP mode %d (valid mode: "
				"-1, 0, 1, 2, 4, 8)\n", radeon_agpmode);
		radeon_agpmode = 0;
		break;
	}
}

int radeon_device_init(struct radeon_device *rdev,
               struct drm_device *ddev,
               struct pci_dev *pdev,
               uint32_t flags)
{
	int r;
	int dma_bits;

    DRM_INFO("radeon: Initializing kernel modesetting.\n");
    rdev->shutdown = false;
    rdev->ddev = ddev;
    rdev->pdev = pdev;
    rdev->flags = flags;
    rdev->family = flags & RADEON_FAMILY_MASK;
    rdev->is_atom_bios = false;
    rdev->usec_timeout = RADEON_MAX_USEC_TIMEOUT;
    rdev->mc.gtt_size = radeon_gart_size * 1024 * 1024;
    rdev->gpu_lockup = false;
	rdev->accel_working = false;
    /* mutex initialization are all done here so we
     * can recall function without having locking issues */
 //   mutex_init(&rdev->cs_mutex);
 //   mutex_init(&rdev->ib_pool.mutex);
 //   mutex_init(&rdev->cp.mutex);
 //   rwlock_init(&rdev->fence_drv.lock);

	/* Set asic functions */
	r = radeon_asic_init(rdev);
	if (r)
		return r;
	radeon_check_arguments(rdev);

	if (rdev->flags & RADEON_IS_AGP && radeon_agpmode == -1) {
		radeon_agp_disable(rdev);
    }

	/* set DMA mask + need_dma32 flags.
	 * PCIE - can handle 40-bits.
	 * IGP - can handle 40-bits (in theory)
	 * AGP - generally dma32 is safest
	 * PCI - only dma32
	 */
	rdev->need_dma32 = false;
	if (rdev->flags & RADEON_IS_AGP)
		rdev->need_dma32 = true;
	if (rdev->flags & RADEON_IS_PCI)
		rdev->need_dma32 = true;

	dma_bits = rdev->need_dma32 ? 32 : 40;
	r = pci_set_dma_mask(rdev->pdev, DMA_BIT_MASK(dma_bits));
    if (r) {
        printk(KERN_WARNING "radeon: No suitable DMA available.\n");
    }

    /* Registers mapping */
    /* TODO: block userspace mapping of io register */
    rdev->rmmio_base = pci_resource_start(rdev->pdev, 2);

    rdev->rmmio_size = pci_resource_len(rdev->pdev, 2);

    rdev->rmmio =  (void*)MapIoMem(rdev->rmmio_base, rdev->rmmio_size,
                                   PG_SW+PG_NOCACHE);

    if (rdev->rmmio == NULL) {
        return -ENOMEM;
    }
    DRM_INFO("register mmio base: 0x%08X\n", (uint32_t)rdev->rmmio_base);
    DRM_INFO("register mmio size: %u\n", (unsigned)rdev->rmmio_size);

	/* if we have > 1 VGA cards, then disable the radeon VGA resources */
	/* this will fail for cards that aren't VGA class devices, just
	 * ignore it */
//	r = vga_client_register(rdev->pdev, rdev, NULL, radeon_vga_set_decode);
//	if (r) {
//		return -EINVAL;
//	}

	r = radeon_init(rdev);
	if (r)
            return r;

	if (rdev->flags & RADEON_IS_AGP && !rdev->accel_working) {
		/* Acceleration not working on AGP card try again
		 * with fallback to PCI or PCIE GART
		 */
		radeon_gpu_reset(rdev);
		radeon_fini(rdev);
		radeon_agp_disable(rdev);
		r = radeon_init(rdev);
		if (r)
		return r;
	}
//	if (radeon_testing) {
//		radeon_test_moves(rdev);
//    }
//	if (radeon_benchmarking) {
//		radeon_benchmark(rdev);
//    }
	return 0;
}


/*
 * Driver load/unload
 */
int radeon_driver_load_kms(struct drm_device *dev, unsigned long flags)
{
    struct radeon_device *rdev;
    int r;

    ENTER();

    rdev = kzalloc(sizeof(struct radeon_device), GFP_KERNEL);
    if (rdev == NULL) {
        return -ENOMEM;
    };

    dev->dev_private = (void *)rdev;

    /* update BUS flag */
    if (drm_device_is_agp(dev)) {
        flags |= RADEON_IS_AGP;
    } else if (drm_device_is_pcie(dev)) {
        flags |= RADEON_IS_PCIE;
    } else {
        flags |= RADEON_IS_PCI;
    }

    /* radeon_device_init should report only fatal error
     * like memory allocation failure or iomapping failure,
     * or memory manager initialization failure, it must
     * properly initialize the GPU MC controller and permit
     * VRAM allocation
     */
    r = radeon_device_init(rdev, dev, dev->pdev, flags);
    if (r) {
        DRM_ERROR("Fatal error while trying to initialize radeon.\n");
        return r;
    }
    /* Again modeset_init should fail only on fatal error
     * otherwise it should provide enough functionalities
     * for shadowfb to run
     */
    if( radeon_modeset )
    {
        r = radeon_modeset_init(rdev);
        if (r) {
            return r;
        }
    };
    return 0;
}

videomode_t usermode;


int drm_get_dev(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    static struct drm_device *dev;
    int ret;

    ENTER();

    dev = kzalloc(sizeof(*dev), 0);
    if (!dev)
        return -ENOMEM;

 //   ret = pci_enable_device(pdev);
 //   if (ret)
 //       goto err_g1;

 //   pci_set_master(pdev);

 //   if ((ret = drm_fill_in_dev(dev, pdev, ent, driver))) {
 //       printk(KERN_ERR "DRM: Fill_in_dev failed.\n");
 //       goto err_g2;
 //   }

    dev->pdev = pdev;
    dev->pci_device = pdev->device;
    dev->pci_vendor = pdev->vendor;

    ret = radeon_driver_load_kms(dev, ent->driver_data );
    if (ret)
        goto err_g4;

    if( radeon_modeset )
        init_display_kms(dev->dev_private, &usermode);
    else
        init_display(dev->dev_private, &usermode);

    LEAVE();

    return 0;

err_g4:
//    drm_put_minor(&dev->primary);
//err_g3:
//    if (drm_core_check_feature(dev, DRIVER_MODESET))
//        drm_put_minor(&dev->control);
//err_g2:
//    pci_disable_device(pdev);
//err_g1:
    free(dev);

    LEAVE();

    return ret;
}

resource_size_t drm_get_resource_start(struct drm_device *dev, unsigned int resource)
{
    return pci_resource_start(dev->pdev, resource);
}

resource_size_t drm_get_resource_len(struct drm_device *dev, unsigned int resource)
{
    return pci_resource_len(dev->pdev, resource);
}


uint32_t __div64_32(uint64_t *n, uint32_t base)
{
        uint64_t rem = *n;
        uint64_t b = base;
        uint64_t res, d = 1;
        uint32_t high = rem >> 32;

        /* Reduce the thing a bit first */
        res = 0;
        if (high >= base) {
                high /= base;
                res = (uint64_t) high << 32;
                rem -= (uint64_t) (high*base) << 32;
        }

        while ((int64_t)b > 0 && b < rem) {
                b = b+b;
                d = d+d;
        }

        do {
                if (rem >= b) {
                        rem -= b;
                        res += d;
                }
                b >>= 1;
                d >>= 1;
        } while (d);

        *n = res;
        return rem;
}


static struct pci_device_id pciidlist[] = {
    radeon_PCI_IDS
};


#define API_VERSION     0x01000100

#define SRV_GETVERSION  0
#define SRV_ENUM_MODES  1
#define SRV_SET_MODE    2

int _stdcall display_handler(ioctl_t *io)
{
    int    retval = -1;
    u32_t *inp;
    u32_t *outp;

    inp = io->input;
    outp = io->output;

    switch(io->io_code)
    {
        case SRV_GETVERSION:
            if(io->out_size==4)
            {
                *outp  = API_VERSION;
                retval = 0;
            }
            break;

        case SRV_ENUM_MODES:
            dbgprintf("SRV_ENUM_MODES inp %x inp_size %x out_size %x\n",
                       inp, io->inp_size, io->out_size );

            if( radeon_modeset &&
                (outp != NULL) && (io->out_size == 4) &&
                (io->inp_size == *outp * sizeof(videomode_t)) )
            {
                retval = get_modes((videomode_t*)inp, outp);
            };
            break;

        case SRV_SET_MODE:
            dbgprintf("SRV_SET_MODE inp %x inp_size %x\n",
                       inp, io->inp_size);

            if(  radeon_modeset   &&
                (inp != NULL) &&
                (io->inp_size == sizeof(videomode_t)) )
            {
                retval = set_user_mode((videomode_t*)inp);
            };
            break;
    };

    return retval;
}

static char  log[256];
static pci_dev_t device;

u32_t drvEntry(int action, char *cmdline)
{
    struct radeon_device *rdev = NULL;

    struct pci_device_id  *ent;

    int     err;
    u32_t   retval = 0;

    if(action != 1)
        return 0;

    if( GetService("DISPLAY") != 0 )
        return 0;

    if( cmdline && *cmdline )
        parse_cmdline(cmdline, &usermode, log, &radeon_modeset);

    if(!dbg_open(log))
    {
        strcpy(log, "/rd/1/drivers/atikms.log");

        if(!dbg_open(log))
        {
            printf("Can't open %s\nExit\n", log);
            return 0;
        };
    }
    dbgprintf("Radeon RC10 cmdline %s\n", cmdline);

    enum_pci_devices();

    ent = find_pci_device(&device, pciidlist);

    if( unlikely(ent == NULL) )
    {
        dbgprintf("device not found\n");
        return 0;
    };

    dbgprintf("device %x:%x\n", device.pci_dev.vendor,
                                device.pci_dev.device);

    err = drm_get_dev(&device.pci_dev, ent);

    rdev = rdisplay->ddev->dev_private;

    if( (rdev->asic == &r600_asic) ||
        (rdev->asic == &rv770_asic))
        r600_2D_test(rdev);
    else if (rdev->asic != &evergreen_asic)
        r100_2D_test(rdev);

    err = RegService("DISPLAY", display_handler);

    if( err != 0)
        dbgprintf("Set DISPLAY handler\n");

    return err;
};

void drm_vblank_post_modeset(struct drm_device *dev, int crtc)
{};

void drm_vblank_pre_modeset(struct drm_device *dev, int crtc)
{};

