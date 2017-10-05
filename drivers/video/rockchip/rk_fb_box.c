/*
 * drivers/video/rockchip/rk_fb.c
 *
 * Copyright (C) ROCKCHIP, Inc.
 * Author:yxj<yxj@rock-chips.com>
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/fb.h>
#include <linux/init.h>
#include <asm/div64.h>
#include <linux/uaccess.h>
#include <linux/rk_fb.h>
#include <linux/linux_logo.h>
#include <linux/dma-mapping.h>

//#define DUAL_LCDC_MAP_TO_SAME_FB

#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>
#include <video/of_display_timing.h>
#include <video/display_timing.h>
#include <dt-bindings/rkfb/rk_fb.h>
#endif

#if defined(CONFIG_ION_ROCKCHIP)
#include <linux/rockchip_ion.h>
#include <linux/rockchip-iovmm.h>
#include <linux/dma-buf.h>
#include <linux/highmem.h>
#endif

#define H_USE_FENCE 1
static struct platform_device *fb_pdev;
struct list_head saved_list;

#if defined(CONFIG_FB_MIRRORING)
int (*video_data_to_mirroring) (struct fb_info *info, u32 yuv_phy[2]);
EXPORT_SYMBOL(video_data_to_mirroring);
#endif

struct rk_fb_reg_win_data g_reg_win_data[4];
static int g_last_win_num;
static int g_first_buf = 1;
static struct rk_fb_trsm_ops *trsm_lvds_ops;
static struct rk_fb_trsm_ops *trsm_edp_ops;
static struct rk_fb_trsm_ops *trsm_mipi_ops;
static int uboot_logo_on;
int support_uboot_display(void)
{
	return uboot_logo_on;
}

int rk_fb_trsm_ops_register(struct rk_fb_trsm_ops *ops, int type)
{
	switch (type) {
	case SCREEN_RGB:
	case SCREEN_LVDS:
	case SCREEN_DUAL_LVDS:
		trsm_lvds_ops = ops;
		break;
	case SCREEN_EDP:
		trsm_edp_ops = ops;
		break;
	case SCREEN_MIPI:
	case SCREEN_DUAL_MIPI:
		trsm_mipi_ops = ops;
		break;
	default:
		printk(KERN_WARNING "%s:un supported transmitter:%d!\n",
		       __func__, type);
		break;
	}
	return 0;
}

struct rk_fb_trsm_ops *rk_fb_trsm_ops_get(int type)
{
	struct rk_fb_trsm_ops *ops;
	switch (type) {
	case SCREEN_RGB:
	case SCREEN_LVDS:
	case SCREEN_DUAL_LVDS:
		ops = trsm_lvds_ops;
		break;
	case SCREEN_EDP:
		ops = trsm_edp_ops;
		break;
	case SCREEN_MIPI:
	case SCREEN_DUAL_MIPI:
		ops = trsm_mipi_ops;
		break;
	default:
		ops = NULL;
		printk(KERN_WARNING "%s:un supported transmitter:%d!\n",
		       __func__, type);
		break;
	}
	return ops;
}

int rk_fb_pixel_width(int data_format)
{
	int pixel_width;
	switch (data_format) {
	case XBGR888:
	case ABGR888:
	case ARGB888:
		pixel_width = 4 * 8;
		break;
	case RGB888:
		pixel_width = 3 * 8;
		break;
	case RGB565:
		pixel_width = 2 * 8;
		break;
	case YUV422:
	case YUV420:
	case YUV444:
		pixel_width = 1 * 8;
		break;
	case YUV422_A:
	case YUV420_A:
	case YUV444_A:
		pixel_width = 10;
		break;
	default:
		printk(KERN_WARNING "%s:un supported format:0x%x\n",
		       __func__, data_format);
		return -EINVAL;
	}
	return pixel_width;
}

static int rk_fb_data_fmt(int data_format, int bits_per_pixel)
{
	int fb_data_fmt;
	if (data_format) {
		switch (data_format) {
		case HAL_PIXEL_FORMAT_RGBX_8888:
			fb_data_fmt = XBGR888;
			break;
		case HAL_PIXEL_FORMAT_RGBA_8888:
			fb_data_fmt = ABGR888;
			break;
		case HAL_PIXEL_FORMAT_BGRA_8888:
			fb_data_fmt = ARGB888;
			break;
		case HAL_PIXEL_FORMAT_RGB_888:
			fb_data_fmt = RGB888;
			break;
		case HAL_PIXEL_FORMAT_RGB_565:
			fb_data_fmt = RGB565;
			break;
		case HAL_PIXEL_FORMAT_YCbCr_422_SP:	/* yuv422 */
			fb_data_fmt = YUV422;
			break;
		case HAL_PIXEL_FORMAT_YCrCb_NV12:	/* YUV420---uvuvuv */
			fb_data_fmt = YUV420;
			break;
		case HAL_PIXEL_FORMAT_YCrCb_444:	/* yuv444 */
			fb_data_fmt = YUV444;
			break;
		case HAL_PIXEL_FORMAT_YCrCb_NV12_10:	/* yuv444 */
			fb_data_fmt = YUV420_A;
			break;
		case HAL_PIXEL_FORMAT_YCbCr_422_SP_10:	/* yuv444 */
			fb_data_fmt = YUV422_A;
			break;
		case HAL_PIXEL_FORMAT_YCrCb_420_SP_10:	/* yuv444 */
			fb_data_fmt = YUV444_A;
			break;
		default:
			printk(KERN_WARNING "%s:un supported format:0x%x\n",
			       __func__, data_format);
			return -EINVAL;
		}
	} else {
		switch (bits_per_pixel) {
		case 32:
			fb_data_fmt = ARGB888;
			break;
		case 16:
			fb_data_fmt = RGB565;
			break;
		default:
			printk(KERN_WARNING
			       "%s:un supported bits_per_pixel:%d\n", __func__,
			       bits_per_pixel);
			break;
		}
	}
	return fb_data_fmt;
}

/*
 * rk display power control parse from dts
 */
int rk_disp_pwr_ctr_parse_dt(struct rk_lcdc_driver *dev_drv)
{
	struct device_node *root = of_get_child_by_name(dev_drv->dev->of_node,
							"power_ctr");
	struct device_node *child;
	struct rk_disp_pwr_ctr_list *pwr_ctr;
	struct list_head *pos;
	enum of_gpio_flags flags;
	u32 val = 0;
	u32 debug = 0;
	int ret;

	INIT_LIST_HEAD(&dev_drv->pwrlist_head);
	if (!root) {
		dev_err(dev_drv->dev, "can't find power_ctr node for lcdc%d\n",
			dev_drv->id);
		return -ENODEV;
	}

	for_each_child_of_node(root, child) {
		pwr_ctr = kmalloc(sizeof(struct rk_disp_pwr_ctr_list),
				  GFP_KERNEL);
		strcpy(pwr_ctr->pwr_ctr.name, child->name);
		if (!of_property_read_u32(child, "rockchip,power_type", &val)) {
			if (val == GPIO) {
				pwr_ctr->pwr_ctr.type = GPIO;
				pwr_ctr->pwr_ctr.gpio = of_get_gpio_flags(child, 0, &flags);
				if (!gpio_is_valid(pwr_ctr->pwr_ctr.gpio)) {
					dev_err(dev_drv->dev, "%s ivalid gpio\n",
						child->name);
					return -EINVAL;
				}
				pwr_ctr->pwr_ctr.atv_val = !(flags & OF_GPIO_ACTIVE_LOW);
				ret = gpio_request(pwr_ctr->pwr_ctr.gpio,
						   child->name);
				if (ret) {
					dev_err(dev_drv->dev,
						"request %s gpio fail:%d\n",
						child->name, ret);
				}

			} else {
				pwr_ctr->pwr_ctr.type = REGULATOR;

			}
		};
		of_property_read_u32(child, "rockchip,delay", &val);
		pwr_ctr->pwr_ctr.delay = val;
		list_add_tail(&pwr_ctr->list, &dev_drv->pwrlist_head);
	}

	of_property_read_u32(root, "rockchip,debug", &debug);

	if (debug) {
		list_for_each(pos, &dev_drv->pwrlist_head) {
			pwr_ctr = list_entry(pos, struct rk_disp_pwr_ctr_list,
					     list);
			printk(KERN_INFO "pwr_ctr_name:%s\n"
			       "pwr_type:%s\n"
			       "gpio:%d\n"
			       "atv_val:%d\n"
			       "delay:%d\n\n",
			       pwr_ctr->pwr_ctr.name,
			       (pwr_ctr->pwr_ctr.type == GPIO) ? "gpio" : "regulator",
			       pwr_ctr->pwr_ctr.gpio,
			       pwr_ctr->pwr_ctr.atv_val,
			       pwr_ctr->pwr_ctr.delay);
		}
	}

	return 0;

}

int rk_disp_pwr_enable(struct rk_lcdc_driver *dev_drv)
{
	struct list_head *pos;
	struct rk_disp_pwr_ctr_list *pwr_ctr_list;
	struct pwr_ctr *pwr_ctr;
	if (list_empty(&dev_drv->pwrlist_head))
		return 0;
	list_for_each(pos, &dev_drv->pwrlist_head) {
		pwr_ctr_list = list_entry(pos, struct rk_disp_pwr_ctr_list,
					  list);
		pwr_ctr = &pwr_ctr_list->pwr_ctr;
		if (pwr_ctr->type == GPIO) {
			gpio_direction_output(pwr_ctr->gpio,pwr_ctr->atv_val);
			mdelay(pwr_ctr->delay);
		}
	}

	return 0;
}

int rk_disp_pwr_disable(struct rk_lcdc_driver *dev_drv)
{
	struct list_head *pos;
	struct rk_disp_pwr_ctr_list *pwr_ctr_list;
	struct pwr_ctr *pwr_ctr;
	if (list_empty(&dev_drv->pwrlist_head))
		return 0;
	list_for_each(pos, &dev_drv->pwrlist_head) {
		pwr_ctr_list = list_entry(pos, struct rk_disp_pwr_ctr_list,
					  list);
		pwr_ctr = &pwr_ctr_list->pwr_ctr;
		if (pwr_ctr->type == GPIO)
			gpio_set_value(pwr_ctr->gpio, !pwr_ctr->atv_val);
	}
	return 0;
}

int rk_fb_video_mode_from_timing(const struct display_timing *dt,
				 struct rk_screen *screen)
{
	screen->mode.pixclock = dt->pixelclock.typ;
	screen->mode.left_margin = dt->hback_porch.typ;
	screen->mode.right_margin = dt->hfront_porch.typ;
	screen->mode.xres = dt->hactive.typ;
	screen->mode.hsync_len = dt->hsync_len.typ;
	screen->mode.upper_margin = dt->vback_porch.typ;
	screen->mode.lower_margin = dt->vfront_porch.typ;
	screen->mode.yres = dt->vactive.typ;
	screen->mode.vsync_len = dt->vsync_len.typ;
	screen->type = dt->screen_type;
	screen->lvds_format = dt->lvds_format;
	screen->face = dt->face;

	if (dt->flags & DISPLAY_FLAGS_PIXDATA_POSEDGE)
		screen->pin_dclk = 1;
	else
		screen->pin_dclk = 0;
	if (dt->flags & DISPLAY_FLAGS_HSYNC_HIGH)
		screen->pin_hsync = 1;
	else
		screen->pin_hsync = 0;
	if (dt->flags & DISPLAY_FLAGS_VSYNC_HIGH)
		screen->pin_vsync = 1;
	else
		screen->pin_vsync = 0;
	if (dt->flags & DISPLAY_FLAGS_DE_HIGH)
		screen->pin_den = 1;
	else
		screen->pin_den = 0;

	return 0;

}

int rk_fb_prase_timing_dt(struct device_node *np, struct rk_screen *screen)
{
	struct display_timings *disp_timing;
	struct display_timing *dt;
	disp_timing = of_get_display_timings(np);
	if (!disp_timing) {
		pr_err("parse display timing err\n");
		return -EINVAL;
	}
	dt = display_timings_get(disp_timing, disp_timing->native_mode);
	rk_fb_video_mode_from_timing(dt, screen);
	return 0;

}

int  rk_fb_calc_fps(struct rk_screen * screen, u32 pixclock)
{
	int x, y;
	unsigned long long hz;
	if (!screen) {
		printk(KERN_ERR "%s:null screen!\n", __func__);
		return 0;
	}
	x = screen->mode.xres + screen->mode.left_margin +
	    screen->mode.right_margin + screen->mode.hsync_len;
	y = screen->mode.yres + screen->mode.upper_margin +
	    screen->mode.lower_margin + screen->mode.vsync_len;

	hz = 1000000000000ULL;	/* 1e12 picoseconds per second */

	hz += (x * y) / 2;
	do_div(hz, x * y);	/* divide by x * y with rounding */

	hz += pixclock / 2;
	do_div(hz, pixclock);	/* divide by pixclock with rounding */

	return hz;
}

char *get_format_string(enum data_format format, char *fmt)
{
	if (!fmt)
		return NULL;
	switch (format) {
	case ARGB888:
		strcpy(fmt, "ARGB888");
		break;
	case RGB888:
		strcpy(fmt, "RGB888");
		break;
	case RGB565:
		strcpy(fmt, "RGB565");
		break;
	case YUV420:
		strcpy(fmt, "YUV420");
		break;
	case YUV422:
		strcpy(fmt, "YUV422");
		break;
	case YUV444:
		strcpy(fmt, "YUV444");
		break;
	case YUV420_A:
		strcpy(fmt, "YUV420_A");
		break;
	case YUV422_A:
		strcpy(fmt, "YUV422_A");
		break;
	case YUV444_A:
		strcpy(fmt, "YUV444_A");
		break;
	case XRGB888:
		strcpy(fmt, "XRGB888");
		break;
	case XBGR888:
		strcpy(fmt, "XBGR888");
		break;
	case ABGR888:
		strcpy(fmt, "XBGR888");
		break;
	default:
		strcpy(fmt, "invalid");
		break;
	}

	return fmt;

}

/*
 * this is for hdmi
 * name: lcdc device name ,lcdc0 , lcdc1
 */
struct rk_lcdc_driver *rk_get_lcdc_drv(char *name)
{
	struct rk_fb *inf = platform_get_drvdata(fb_pdev);
	int i = 0;
	for (i = 0; i < inf->num_lcdc; i++) {
		if (!strcmp(inf->lcdc_dev_drv[i]->name, name))
			break;
	}
	return inf->lcdc_dev_drv[i];

}

static struct rk_lcdc_driver *rk_get_prmry_lcdc_drv(void)
{
	struct rk_fb *inf = NULL;
	struct rk_lcdc_driver *dev_drv = NULL;
	int i = 0;

	if (likely(fb_pdev))
		inf = platform_get_drvdata(fb_pdev);
	else
		return NULL;

	for (i = 0; i < inf->num_lcdc; i++) {
		if (inf->lcdc_dev_drv[i]->prop == PRMRY) {
			dev_drv = inf->lcdc_dev_drv[i];
			break;
		}
	}

	return dev_drv;
}

/*
 * get one frame time of the prmry screen, unit: us
 */
u32 rk_fb_get_prmry_screen_ft(void)
{
	struct rk_lcdc_driver *dev_drv = rk_get_prmry_lcdc_drv();
	uint32_t htotal, vtotal, pixclock_ps;
	u64 pix_total, ft_us;

	if (unlikely(!dev_drv))
		return 0;

	pixclock_ps = dev_drv->pixclock;

	vtotal = (dev_drv->cur_screen->mode.upper_margin +
		 dev_drv->cur_screen->mode.lower_margin +
		 dev_drv->cur_screen->mode.yres +
		 dev_drv->cur_screen->mode.vsync_len);
	htotal = (dev_drv->cur_screen->mode.left_margin +
		 dev_drv->cur_screen->mode.right_margin +
		 dev_drv->cur_screen->mode.xres +
		 dev_drv->cur_screen->mode.hsync_len);
	pix_total = htotal * vtotal;
	ft_us = pix_total * pixclock_ps;
	do_div(ft_us, 1000000);
	if (dev_drv->frame_time.ft == 0)
		dev_drv->frame_time.ft = ft_us;

	ft_us = dev_drv->frame_time.framedone_t - dev_drv->frame_time.last_framedone_t;
	do_div(ft_us, 1000);
	ft_us = min(dev_drv->frame_time.ft, (u32)ft_us);
	if (ft_us != 0)
		dev_drv->frame_time.ft = ft_us;

	return dev_drv->frame_time.ft;
}

/*
 * get the vblanking time of the prmry screen, unit: us
 */
u32 rk_fb_get_prmry_screen_vbt(void)
{
	struct rk_lcdc_driver *dev_drv = rk_get_prmry_lcdc_drv();
	uint32_t htotal, vblank, pixclock_ps;
	u64 pix_blank, vbt_us;

	if (unlikely(!dev_drv))
		return 0;

	pixclock_ps = dev_drv->pixclock;

	htotal = (dev_drv->cur_screen->mode.left_margin +
		 dev_drv->cur_screen->mode.right_margin +
		 dev_drv->cur_screen->mode.xres +
		 dev_drv->cur_screen->mode.hsync_len);
	vblank = (dev_drv->cur_screen->mode.upper_margin +
		 dev_drv->cur_screen->mode.lower_margin +
		 dev_drv->cur_screen->mode.vsync_len);
	pix_blank = htotal * vblank;
	vbt_us = pix_blank * pixclock_ps;
	do_div(vbt_us, 1000000);
	return (u32)vbt_us;
}

/*
 * get the frame done time of the prmry screen, unit: us
 */
u64 rk_fb_get_prmry_screen_framedone_t(void)
{
	struct rk_lcdc_driver *dev_drv = rk_get_prmry_lcdc_drv();

	return dev_drv->frame_time.framedone_t;
}

#if 0
static struct rk_lcdc_driver *rk_get_extend_lcdc_drv(void)
{
	struct rk_fb *inf = NULL;
	struct rk_lcdc_driver *dev_drv = NULL;
	int i = 0;

	if (likely(fb_pdev))
		inf = platform_get_drvdata(fb_pdev);
	else
		return NULL;

	for (i = 0; i < inf->num_lcdc; i++) {
		if (inf->lcdc_dev_drv[i]->prop == EXTEND) {
			dev_drv = inf->lcdc_dev_drv[i];
			break;
		}
	}

	return dev_drv;
}
#endif

u32 rk_fb_get_prmry_screen_pixclock(void)
{
	struct rk_lcdc_driver *dev_drv = rk_get_prmry_lcdc_drv();
	return dev_drv->pixclock;
}

int rk_fb_poll_prmry_screen_vblank(void)
{
	struct rk_lcdc_driver *dev_drv = rk_get_prmry_lcdc_drv();
	if (likely(dev_drv)) {
		if (dev_drv->ops->poll_vblank)
			return dev_drv->ops->poll_vblank(dev_drv);
		else
			return RK_LF_STATUS_NC;
	} else
		return RK_LF_STATUS_NC;
}

bool rk_fb_poll_wait_frame_complete(void)
{
	uint32_t timeout = RK_LF_MAX_TIMEOUT;
	struct rk_lcdc_driver *dev_drv = rk_get_prmry_lcdc_drv();

	if (likely(dev_drv)) {
		if (dev_drv->ops->set_irq_to_cpu)
			dev_drv->ops->set_irq_to_cpu(dev_drv, 0);
	}

	if (rk_fb_poll_prmry_screen_vblank() == RK_LF_STATUS_NC) {
		if (likely(dev_drv)) {
			if (dev_drv->ops->set_irq_to_cpu)
				dev_drv->ops->set_irq_to_cpu(dev_drv, 1);
		}
		return false;
	}

	while (!(rk_fb_poll_prmry_screen_vblank() == RK_LF_STATUS_FR) && --timeout)
		;
	while (!(rk_fb_poll_prmry_screen_vblank() == RK_LF_STATUS_FC) && --timeout)
		;

	if (likely(dev_drv)) {
		if (dev_drv->ops->set_irq_to_cpu)
			dev_drv->ops->set_irq_to_cpu(dev_drv, 1);
	}

	return true;
}


/* rk_fb_get_sysmmu_device_by_compatible()
 * @compt: dts device compatible name
 * return value: success: pointer to the device inside of platform device
 *               fail: NULL
 */
struct device *rk_fb_get_sysmmu_device_by_compatible(const char *compt)
{
        struct device_node *dn = NULL;
        struct platform_device *pd = NULL;
        struct device *ret = NULL ;

        dn = of_find_compatible_node(NULL, NULL, compt);
        if (!dn) {
                printk("can't find device node %s \r\n", compt);
                return NULL;
	}

        pd = of_find_device_by_node(dn);
        if (!pd) {
                printk("can't find platform device in device node %s \r\n", compt);
                return  NULL;
        }
        ret = &pd->dev;

        return ret;
}

#ifdef CONFIG_IOMMU_API
void rk_fb_platform_set_sysmmu(struct device *sysmmu, struct device *dev)
{
        dev->archdata.iommu = sysmmu;
}
#else
void rk_fb_platform_set_sysmmu(struct device *sysmmu, struct device *dev)
{

}
#endif

static int rk_fb_open(struct fb_info *info, int user)
{
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	int win_id;

	win_id = dev_drv->ops->fb_get_win_id(dev_drv, info->fix.id);
	/* if this win aready opened ,no need to reopen */
	dev_drv->win[win_id]->logicalstate = 1;	
	if (dev_drv->win[win_id]->state)
		return 0;
	else if(dev_drv->enable || user == 2)
		dev_drv->ops->open(dev_drv, win_id, 1);
	return 0;
}

static int rk_fb_close(struct fb_info *info, int user)
{
#if 0
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct rk_lcdc_win *win = NULL;
	int win_id = dev_drv->ops->fb_get_win_id(dev_drv, info->fix.id);
	if (win_id >= 0) {
		win = dev_drv->win[win_id];
		info->fix.smem_start = win->reserved;

		info->var.xres = dev_drv->screen0->mode.xres;
		info->var.yres = dev_drv->screen0->mode.yres;
		info->var.grayscale |=
		    (info->var.xres << 8) + (info->var.yres << 20);
		info->var.xres_virtual = info->var.xres;
		info->var.yres_virtual = info->var.yres;
#if defined(CONFIG_LOGO_LINUX_BMP)
		info->var.bits_per_pixel = 32;
#else
		info->var.bits_per_pixel = 16;
#endif

		info->fix.line_length =
		    (info->var.xres_virtual) * (info->var.bits_per_pixel >> 3);
		info->var.width = dev_drv->screen0->width;
		info->var.height = dev_drv->screen0->height;
		info->var.pixclock = dev_drv->pixclock;
		info->var.left_margin = dev_drv->screen0->mode.left_margin;
		info->var.right_margin = dev_drv->screen0->mode.right_margin;
		info->var.upper_margin = dev_drv->screen0->mode.upper_margin;
		info->var.lower_margin = dev_drv->screen0->mode.lower_margin;
		info->var.vsync_len = dev_drv->screen0->mode.vsync_len;
		info->var.hsync_len = dev_drv->screen0->mode.hsync_len;
	}
#endif
	return 0;
}

static int rk_fb_pan_display(struct fb_var_screeninfo *var,
			     struct fb_info *info)
{
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct fb_fix_screeninfo *fix = &info->fix;
	int win_id = 0;
	struct rk_lcdc_win *win = NULL;
	struct rk_screen *screen = dev_drv->cur_screen;

	u32 xoffset = var->xoffset;
	u32 yoffset = var->yoffset;
	u32 xvir = var->xres_virtual;
	/* u32 yvir = var->yres_virtual; */
	/* u8 data_format = var->nonstd&0xff; */

	u8 pixel_width;
	u32 vir_width_bit;
	u32 stride, uv_stride;
	u32 stride_32bit_1;
	u32 stride_32bit_2;
	u16 uv_x_off, uv_y_off, uv_y_act;
	u8 is_pic_yuv = 0;

	win_id = dev_drv->ops->fb_get_win_id(dev_drv, info->fix.id);
	if (win_id < 0)
		return -ENODEV;
	else
		win = dev_drv->win[win_id];

	pixel_width = rk_fb_pixel_width(win->format);
	vir_width_bit = pixel_width * xvir;
	if((win->format == YUV420_A)||(win->format == YUV422_A)||(win->format == YUV444_A)){
		vir_width_bit = xvir * 8;
		stride_32bit_1 = xvir;
		stride_32bit_2 = xvir*2;
	}else{
		vir_width_bit = pixel_width * xvir;
		stride_32bit_1	= ((vir_width_bit   + 31 ) & (~31 ))/8; //pixel_width = byte_num *8
		stride_32bit_2	= ((vir_width_bit*2 + 31 ) & (~31 ))/8; //pixel_width = byte_num *8
	}


	switch (win->format) {
	case YUV422:
	case YUV422_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_1 >> 1;
		uv_x_off = xoffset >> 1;
		uv_y_off = yoffset;
		fix->line_length = stride;
		uv_y_act = win->area[0].yact >> 1;
		break;
	case YUV420:		/* 420sp */
	case YUV420_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_1;
		uv_x_off = xoffset;
		uv_y_off = yoffset >> 1;
		fix->line_length = stride;
		uv_y_act = win->area[0].yact >> 1;
		break;
	case YUV444:
	case YUV444_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_2;
		uv_x_off = xoffset * 2;
		uv_y_off = yoffset;
		fix->line_length = stride << 2;
		uv_y_act = win->area[0].yact;
		break;
	default:
		stride = stride_32bit_1;	/* default rgb */
		fix->line_length = stride;
		break;
	}

	/* x y mirror ,jump line */
	if (screen->y_mirror == 1) {
		if (screen->interlace == 1) {
			win->area[0].y_offset = yoffset * stride * 2 +
			    ((win->area[0].yact - 1) * 2 + 1) * stride +
			    xoffset * pixel_width / 8;
		} else {
			win->area[0].y_offset = yoffset * stride +
			    (win->area[0].yact - 1) * stride +
			    xoffset * pixel_width / 8;
		}
	} else {
		if (screen->interlace == 1) {
			win->area[0].y_offset =
			    yoffset * stride * 2 + xoffset * pixel_width / 8;
		} else {
			win->area[0].y_offset =
			    yoffset * stride + xoffset * pixel_width / 8;
		}
	}
	if (is_pic_yuv == 1) {
		if (screen->y_mirror == 1) {
			if (screen->interlace == 1) {
				win->area[0].c_offset =
				    uv_y_off * uv_stride * 2 +
				    ((uv_y_act - 1) * 2 + 1) * uv_stride +
				    uv_x_off * pixel_width / 8;
			} else {
				win->area[0].c_offset = uv_y_off * uv_stride +
				    (uv_y_act - 1) * uv_stride +
				    uv_x_off * pixel_width / 8;
			}
		} else {
			if (screen->interlace == 1) {
				win->area[0].c_offset =
				    uv_y_off * uv_stride * 2 +
				    uv_x_off * pixel_width / 8;
			} else {
				win->area[0].c_offset =
				    uv_y_off * uv_stride +
				    uv_x_off * pixel_width / 8;
			}
		}		
	}

	win->area[0].smem_start = fix->smem_start;
	win->area[0].cbr_start = fix->mmio_start;
	win->area[0].state = 1;
	win->area_num = 1;
	if(var->activate & FB_ACTIVATE_FORCE) {
		dev_drv->ops->pan_display(dev_drv, win_id);
		dev_drv->ops->cfg_done(dev_drv);
	}
	#ifdef	CONFIG_FB_MIRRORING
	if (video_data_to_mirroring)
		video_data_to_mirroring(info, NULL);
	#endif
		
	return 0;
}

static int rk_fb_get_list_stat(struct rk_lcdc_driver *dev_drv)
{
	int i, j;
	i = list_empty(&dev_drv->update_regs_list);
	j = list_empty(&dev_drv->saved_list);
	return i == j ? 0 : 1;

}

void rk_fd_fence_wait(struct rk_lcdc_driver *dev_drv, struct sync_fence *fence)
{
	int err = sync_fence_wait(fence, 1000);

	if (err >= 0)
		return;

	if (err == -ETIME)
		err = sync_fence_wait(fence, 10 * MSEC_PER_SEC);

	if (err < 0)
		printk("error waiting on fence\n");
}

static int rk_fb_copy_from_loader(struct fb_info *info)
{
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	void *dst = info->screen_base;
	u32 dsp_addr[4];
	u32 src;
	u32 i;
	struct rk_lcdc_win *win = dev_drv->win[0];
	u32 size = (win->area[0].xact) * (win->area[0].yact) << 2;
	dev_drv->ops->get_dsp_addr(dev_drv, dsp_addr);
	src = dsp_addr[0];
	dev_info(info->dev, "copy fb data %d x %d  from  dst_addr:%08x\n",
		 win->area[0].xact, win->area[0].yact, src);
	for (i = 0; i < size; i += PAGE_SIZE) {
		void *page = phys_to_page(i + src);
		void *from_virt = kmap(page);
		void *to_virt = dst + i;
		memcpy(to_virt, from_virt, PAGE_SIZE);
	}
	return 0;
}

#ifdef CONFIG_ROCKCHIP_IOMMU
static int g_last_addr[4];
int g_last_timeout;
u32 freed_addr[10];
u32 freed_index;

#define DUMP_CHUNK 256
char buf[PAGE_SIZE];

int rk_fb_sysmmu_fault_handler(struct device *dev,
			       enum rk_iommu_inttype itype,
			       unsigned long pgtable_base,
			       unsigned long fault_addr, unsigned int status)
{
	struct rk_lcdc_driver *dev_drv = rk_get_prmry_lcdc_drv();
	int i = 0;
	static int page_fault_cnt;
	if ((page_fault_cnt++) >= 10)
		return 0;
	pr_err
	    ("PAGE FAULT occurred at 0x%lx (Page table base: 0x%lx),status=%d\n",
	     fault_addr, pgtable_base, status);
	printk("last config addr:\n" "win0:0x%08x\n" "win1:0x%08x\n"
	       "win2:0x%08x\n" "win3:0x%08x\n", g_last_addr[0], g_last_addr[1],
	       g_last_addr[2], g_last_addr[3]);
	printk("last freed buffer:\n");
	for (i = 0; (freed_addr[i] != 0xfefefefe) && freed_addr[i]; i++)
		printk("%d:0x%08x\n", i, freed_addr[i]);
	printk("last timeout:%d\n", g_last_timeout);
	dev_drv->ops->get_disp_info(dev_drv, buf,0) ;
	for (i = 0; i < PAGE_SIZE; i += DUMP_CHUNK) {
		if ((PAGE_SIZE - i) > DUMP_CHUNK) {
			char c = buf[i + DUMP_CHUNK];
			buf[i + DUMP_CHUNK] = 0;
			pr_cont("%s", buf + i);
			buf[i + DUMP_CHUNK] = c;
		} else {
			buf[PAGE_SIZE -1] = 0;
			pr_cont("%s", buf + i);
		}
	}

	return 0;
}
#endif

void rk_fb_free_dma_buf(struct rk_lcdc_driver *dev_drv,
			struct rk_fb_reg_win_data *reg_win_data)
{
	int i, index_buf;
	struct rk_fb_reg_area_data *area_data;
	struct rk_fb *rk_fb = platform_get_drvdata(fb_pdev);

	for (i = 0; i < reg_win_data->area_num; i++) {
		area_data = &reg_win_data->reg_area_data[i];
		index_buf = area_data->index_buf;
#if defined(CONFIG_ROCKCHIP_IOMMU)
		if (dev_drv->iommu_enabled) {
			ion_unmap_iommu(dev_drv->dev, rk_fb->ion_client,
					area_data->ion_handle);
			freed_addr[freed_index++] = area_data->smem_start;
		}
#endif
		if (area_data->ion_handle != NULL) {
			ion_unmap_kernel(rk_fb->ion_client,
					 area_data->ion_handle);
			ion_free(rk_fb->ion_client, area_data->ion_handle);
		}
		if (area_data->acq_fence)
			sync_fence_put(area_data->acq_fence);
	}
	memset(reg_win_data, 0, sizeof(struct rk_fb_reg_win_data));
}

static void rk_fb_update_driver(struct rk_lcdc_win *win,
				struct rk_fb_reg_win_data *reg_win_data)
{
	int i = 0;
/*
	struct rk_lcdc_win *win;
	win = dev_drv->win[reg_win_data->win_id];
*/
	win->area_num = reg_win_data->area_num;
	win->format = reg_win_data->data_format;
	win->id = reg_win_data->win_id;
	win->z_order = reg_win_data->z_order;

	if (reg_win_data->reg_area_data[0].smem_start > 0) {
		win->state = 1;
		win->area_num = reg_win_data->area_num;
		win->format = reg_win_data->data_format;
		win->id = reg_win_data->win_id;
		win->z_order = reg_win_data->z_order;
		win->area[0].uv_vir_stride =
		    reg_win_data->reg_area_data[0].uv_vir_stride;

#if !defined(RK_FB_ROTATE) && defined(CONFIG_THREE_FB_BUFFER)
		/* TODO Mofidy if HDMI info is change to hwc */
		win->area[0].cbr_start =
		    reg_win_data->reg_area_data[0].cbr_start;
#endif
		win->area[0].c_offset = reg_win_data->reg_area_data[0].c_offset;
		win->alpha_en = reg_win_data->alpha_en;
		win->alpha_mode = reg_win_data->alpha_mode;
		win->g_alpha_val = reg_win_data->g_alpha_val;
		for (i = 0; i < RK_WIN_MAX_AREA; i++) {
			if (reg_win_data->reg_area_data[i].smem_start > 0) {
#if !defined(RK_FB_ROTATE) && defined(CONFIG_THREE_FB_BUFFER)
				win->area[i].smem_start =
				    reg_win_data->reg_area_data[i].smem_start;
#endif
				win->area[i].xpos =
				    reg_win_data->reg_area_data[i].xpos;
				win->area[i].ypos =
				    reg_win_data->reg_area_data[i].ypos;
				win->area[i].xsize =
				    reg_win_data->reg_area_data[i].xsize;
				win->area[i].ysize =
				    reg_win_data->reg_area_data[i].ysize;
				win->area[i].xact =
				    reg_win_data->reg_area_data[i].xact;
				win->area[i].yact =
				    reg_win_data->reg_area_data[i].yact;
				win->area[i].xvir =
				    reg_win_data->reg_area_data[i].xvir;
				win->area[i].yvir =
				    reg_win_data->reg_area_data[i].yvir;
				win->area[i].y_offset =
				    reg_win_data->reg_area_data[i].y_offset;
				win->area[i].y_vir_stride =
				    reg_win_data->reg_area_data[i].y_vir_stride;
				win->area[i].state = 1;
			} else {
				win->area[i].state = 0;
			}
		}
	} else {
	/*
		win->state = 0;
		win->z_order = -1;
	*/
	}

}

static struct rk_fb_reg_win_data *rk_fb_get_win_data(struct rk_fb_reg_data
						     *regs, int win_id)
{
	int i;
	struct rk_fb_reg_win_data *win_data = NULL;
	for (i = 0; i < regs->win_num; i++) {
		if (regs->reg_win_data[i].win_id == win_id) {
			win_data = &(regs->reg_win_data[i]);
			break;
		}
	}

	return win_data;
}

static void rk_fb_update_reg(struct rk_lcdc_driver *dev_drv,
			     struct rk_fb_reg_data *regs)
{
	int i,j;
	struct rk_lcdc_win *win;
	ktime_t timestamp = dev_drv->vsync_info.timestamp;
	struct rk_fb_reg_win_data *win_data;
	bool wait_for_vsync;
	int count = 100;
	unsigned int dsp_addr[4];
	long timeout;

	/* acq_fence wait */
	for (i = 0; i < regs->win_num; i++) {
		win_data = &regs->reg_win_data[i];
		for (j = 0; j < RK_WIN_MAX_AREA; j++) {
			if (win_data->reg_area_data[j].acq_fence) {
				/* printk("acq_fence wait!!!!!\n"); */
				rk_fd_fence_wait(dev_drv, win_data->reg_area_data[j].acq_fence);
			}
		}
	}

	for (i = 0; i < dev_drv->lcdc_win_num; i++) {
		win = dev_drv->win[i];
		win_data = rk_fb_get_win_data(regs, i);
		if (win_data) {
			rk_fb_update_driver(win, win_data);
			win->state = 1;
			dev_drv->ops->set_par(dev_drv, i);
			dev_drv->ops->pan_display(dev_drv, i);
#if defined(CONFIG_ROCKCHIP_IOMMU)
			if (dev_drv->iommu_enabled) {
				g_last_addr[i] = win_data->reg_area_data[0].smem_start +
					win_data->reg_area_data[0].y_offset;
			}
#endif
		} else {
			win->z_order = -1;
			win->state = 0;
		}
	}
	dev_drv->ops->ovl_mgr(dev_drv, 0, 1);

	dev_drv->ops->cfg_done(dev_drv);

	do {
		timestamp = dev_drv->vsync_info.timestamp;
		timeout = wait_event_interruptible_timeout(dev_drv->vsync_info.wait,
				ktime_compare(dev_drv->vsync_info.timestamp, timestamp) > 0,
				msecs_to_jiffies(50));
		dev_drv->ops->get_dsp_addr(dev_drv, dsp_addr);
		wait_for_vsync = false;
		for (i = 0; i < dev_drv->lcdc_win_num; i++) {
			if (dev_drv->win[i]->state == 1) {
				u32 new_start =
				    dev_drv->win[i]->area[0].smem_start +
				    dev_drv->win[i]->area[0].y_offset;
				u32 reg_start = dsp_addr[i];

				if (unlikely(new_start != reg_start)) {
					wait_for_vsync = true;
					dev_info(dev_drv->dev,
					       "win%d:new_addr:0x%08x cur_addr:0x%08x--%d\n",
					       i, new_start, reg_start, 101 - count);
					break;
				}
			}
		}
	} while (wait_for_vsync && count--);
#ifdef H_USE_FENCE
	sw_sync_timeline_inc(dev_drv->timeline, 1);
#endif

	if (dev_drv->front_regs) {
#if defined(CONFIG_ROCKCHIP_IOMMU)
		if (dev_drv->iommu_enabled) {
			freed_index = 0;
			g_last_timeout = timeout;
		}
#endif
		mutex_lock(&dev_drv->front_lock);

		for (i = 0; i < dev_drv->front_regs->win_num; i++) {
			win_data = &dev_drv->front_regs->reg_win_data[i];
			rk_fb_free_dma_buf(dev_drv, win_data);
		}
		kfree(dev_drv->front_regs);

		mutex_unlock(&dev_drv->front_lock);
#if defined(CONFIG_ROCKCHIP_IOMMU)
		if (dev_drv->iommu_enabled)
			freed_addr[freed_index] = 0xfefefefe;
#endif
	}
	mutex_lock(&dev_drv->front_lock);

	dev_drv->front_regs = regs;

	mutex_unlock(&dev_drv->front_lock);
	g_last_win_num = regs->win_num;
	g_first_buf = 0;

}

static void rk_fb_update_regs_handler(struct kthread_work *work)
{
	struct rk_lcdc_driver *dev_drv =
	    container_of(work, struct rk_lcdc_driver, update_regs_work);
	struct rk_fb_reg_data *data, *next;
	/* struct list_head saved_list; */

	mutex_lock(&dev_drv->update_regs_list_lock);
	dev_drv->saved_list = dev_drv->update_regs_list;
	list_replace_init(&dev_drv->update_regs_list, &dev_drv->saved_list);
	mutex_unlock(&dev_drv->update_regs_list_lock);

	mutex_lock(&dev_drv->win_config);
	list_for_each_entry_safe(data, next, &dev_drv->saved_list, list) {
		rk_fb_update_reg(dev_drv, data);
		list_del(&data->list);
	}
	mutex_unlock(&dev_drv->win_config);
	if (dev_drv->wait_fs && list_empty(&dev_drv->update_regs_list))
		wake_up(&dev_drv->update_regs_wait);
}

static int rk_fb_check_config_var(struct rk_fb_area_par *area_par,
				  struct rk_screen *screen)
{
	if ((area_par->x_offset + area_par->xact > area_par->xvir) ||
	    (area_par->xact <= 0) || (area_par->yact <= 0) ||
	    (area_par->xvir <= 0) || (area_par->yvir <= 0)) {
		pr_err("check config var fail 0:\n"
		       "x_offset=%d,xact=%d,xvir=%d\n",
		       area_par->x_offset, area_par->xact, area_par->xvir);
		return -EINVAL;
	}

	if ((area_par->xpos + area_par->xsize > screen->mode.xres) ||
	    (area_par->ypos + area_par->ysize > screen->mode.yres) ||
	    (area_par->xsize <= 0) || (area_par->ysize <= 0)) {
		pr_err("check config var fail 1:\n"
		       "xpos=%d,xsize=%d,xres=%d\n"
		       "ypos=%d,ysize=%d,yres=%d\n",
		       area_par->xpos, area_par->xsize, screen->mode.xres,
		       area_par->ypos, area_par->ysize, screen->mode.yres);
		return -EINVAL;
	}
	return 0;
}

static int rk_fb_set_win_buffer(struct fb_info *info,
				struct rk_fb_win_par *win_par,
				struct rk_fb_reg_win_data *reg_win_data)
{
	struct rk_fb *rk_fb = dev_get_drvdata(info->device);
	struct fb_fix_screeninfo *fix = &info->fix;
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct rk_screen *screen = dev_drv->cur_screen;
	struct fb_info *fbi = rk_fb->fb[0];
	int i, ion_fd, acq_fence_fd;
	u32 xvir, yvir;
	u32 xoffset, yoffset;

	struct ion_handle *hdl;
	size_t len;
	int index_buf;
	u8 fb_data_fmt;
	u8 pixel_width;
	u32 vir_width_bit;
	u32 stride, uv_stride;
	u32 stride_32bit_1;
	u32 stride_32bit_2;
	u16 uv_x_off, uv_y_off, uv_y_act;
	u8 is_pic_yuv = 0;
	u8 ppixel_a = 0, global_a = 0;
	ion_phys_addr_t phy_addr;
	int ret;

	reg_win_data->reg_area_data[0].smem_start = -1;
	reg_win_data->area_num = 0;
	fbi = rk_fb->fb[reg_win_data->win_id];
	if (win_par->area_par[0].phy_addr == 0) {
		for (i = 0; i < RK_WIN_MAX_AREA; i++) {
			ion_fd = win_par->area_par[i].ion_fd;
			if (ion_fd > 0) {
				hdl =
				    ion_import_dma_buf(rk_fb->ion_client,
						       ion_fd);
				if (IS_ERR(hdl)) {
					pr_info
					    ("%s: Could not import handle: %d\n",
					     __func__, (int)hdl);
					/*return -EINVAL; */
					break;
				}
				fbi->screen_base =
				    ion_map_kernel(rk_fb->ion_client, hdl);
				reg_win_data->area_num++;
				reg_win_data->reg_area_data[i].ion_handle = hdl;
#ifndef CONFIG_ROCKCHIP_IOMMU
				ret = ion_phys(rk_fb->ion_client, hdl, &phy_addr,
						&len);
#else
				if (dev_drv->iommu_enabled)
					ret = ion_map_iommu(dev_drv->dev,
								rk_fb->ion_client,
								hdl,
								(unsigned long *)&phy_addr,
								(unsigned long *)&len);
				else
					ret = ion_phys(rk_fb->ion_client, hdl,
							&phy_addr, &len);
#endif
				if (ret < 0) {
					dev_err(fbi->dev, "ion map to get phy addr failed\n");
					ion_free(rk_fb->ion_client, hdl);
					return -ENOMEM;
				}
				reg_win_data->reg_area_data[i].smem_start = phy_addr;
				reg_win_data->area_buf_num++;
				reg_win_data->reg_area_data[i].index_buf = 1;
			}
		}
	} else {
		reg_win_data->reg_area_data[0].smem_start =
		    win_par->area_par[0].phy_addr;
		reg_win_data->area_num = 1;
		fbi->screen_base = phys_to_virt(win_par->area_par[0].phy_addr);
	}

	if (reg_win_data->area_num == 0)
		return 0;

	for (i = 0; i < reg_win_data->area_num; i++) {
		acq_fence_fd = win_par->area_par[i].acq_fence_fd;
		index_buf = reg_win_data->reg_area_data[i].index_buf;
		if ((acq_fence_fd > 0) && (index_buf == 1)) {
			reg_win_data->reg_area_data[i].acq_fence =
			    sync_fence_fdget(win_par->area_par[i].acq_fence_fd);
		}
	}
	fb_data_fmt = rk_fb_data_fmt(win_par->data_format, 0);
	reg_win_data->data_format = fb_data_fmt;
	pixel_width = rk_fb_pixel_width(fb_data_fmt);

	ppixel_a = ((fb_data_fmt == ARGB888)
		    || (fb_data_fmt == ABGR888)) ? 1 : 0;
	global_a = (win_par->g_alpha_val == 0) ? 0 : 1;
	reg_win_data->alpha_en = ppixel_a | global_a;
	reg_win_data->g_alpha_val = win_par->g_alpha_val;
	reg_win_data->alpha_mode = win_par->alpha_mode;
	if (reg_win_data->reg_area_data[0].smem_start > 0) {
		reg_win_data->z_order = win_par->z_order;
		reg_win_data->win_id = win_par->win_id;
	} else {
		reg_win_data->z_order = -1;
		reg_win_data->win_id = -1;
	}
	for (i = 0; i < reg_win_data->area_num; i++) {
		rk_fb_check_config_var(&win_par->area_par[i], screen);
		/* visiable pos in panel */
		reg_win_data->reg_area_data[i].xpos = win_par->area_par[i].xpos;
		reg_win_data->reg_area_data[i].ypos = win_par->area_par[i].ypos;

		/* realy size in panel */
		reg_win_data->reg_area_data[i].xsize = win_par->area_par[i].xsize;
		reg_win_data->reg_area_data[i].ysize = win_par->area_par[i].ysize;

		/* realy size in panel */
		reg_win_data->reg_area_data[i].xact = win_par->area_par[i].xact;
		reg_win_data->reg_area_data[i].yact = win_par->area_par[i].yact;

		xoffset = win_par->area_par[i].x_offset;	/* buf offset */
		yoffset = win_par->area_par[i].y_offset;
		xvir = win_par->area_par[i].xvir;
		reg_win_data->reg_area_data[i].xvir = xvir;
		yvir = win_par->area_par[i].yvir;
		reg_win_data->reg_area_data[i].yvir = yvir;

		if((fb_data_fmt == YUV420_A)||(fb_data_fmt == YUV422_A)||(fb_data_fmt == YUV444_A)){
			vir_width_bit = xvir * 8;
			stride_32bit_1 = xvir;
			stride_32bit_2 = xvir*2;
		} else {
			vir_width_bit = pixel_width * xvir;
			/* pixel_width = byte_num*8 */
			stride_32bit_1 = ((vir_width_bit + 31) & (~31)) / 8;
			stride_32bit_2 = ((vir_width_bit * 2 + 31) & (~31)) / 8;
		}

		stride = stride_32bit_1;	/* default rgb */
		fix->line_length = stride;
		reg_win_data->reg_area_data[i].y_vir_stride = stride >> 2;

		/* x y mirror ,jump line
		 * reg_win_data->reg_area_data[i].y_offset =
		 *		yoffset*stride+xoffset*pixel_width/8;
		 */
		if (screen->y_mirror == 1) {
			if (screen->interlace == 1) {
				reg_win_data->reg_area_data[i].y_offset =
				    yoffset * stride * 2 +
				    ((reg_win_data->reg_area_data[i].yact - 1) * 2 + 1) * stride +
				    xoffset * pixel_width / 8;
			} else {
				reg_win_data->reg_area_data[i].y_offset =
				    yoffset * stride +
				    (reg_win_data->reg_area_data[i].yact - 1) * stride +
				    xoffset * pixel_width / 8;
			}
		} else {
			if (screen->interlace == 1) {
				reg_win_data->reg_area_data[i].y_offset =
				    yoffset * stride * 2 +
				    xoffset * pixel_width / 8;
			} else {
				reg_win_data->reg_area_data[i].y_offset =
				    yoffset * stride +
				    xoffset * pixel_width / 8;
			}
		}

	}
	switch (fb_data_fmt) {
	case YUV422:
	case YUV422_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_1 >> 1;
		uv_x_off = xoffset >> 1;
		uv_y_off = yoffset;
		fix->line_length = stride;
		uv_y_act = win_par->area_par[0].yact >> 1;
		break;
	case YUV420:		/* 420sp */
	case YUV420_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_1;
		uv_x_off = xoffset;
		uv_y_off = yoffset >> 1;
		fix->line_length = stride;
		uv_y_act = win_par->area_par[0].yact >> 1;
		break;
	case YUV444:
	case YUV444_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_2;
		uv_x_off = xoffset * 2;
		uv_y_off = yoffset;
		fix->line_length = stride << 2;
		uv_y_act = win_par->area_par[0].yact;
		break;
	default:
		break;
	}
	if (is_pic_yuv == 1) {
		reg_win_data->reg_area_data[0].cbr_start =
		    reg_win_data->reg_area_data[0].smem_start + xvir * yvir;
		reg_win_data->reg_area_data[0].uv_vir_stride = uv_stride >> 2;
		if (screen->y_mirror == 1) {
			if (screen->interlace == 1) {
				reg_win_data->reg_area_data[0].c_offset =
				    uv_y_off * uv_stride * 2 +
				    ((uv_y_act - 1) * 2 + 1) * uv_stride +
				    uv_x_off * pixel_width / 8;
			} else {
				reg_win_data->reg_area_data[0].c_offset =
				    uv_y_off * uv_stride +
				    (uv_y_act - 1) * uv_stride +
				    uv_x_off * pixel_width / 8;
			}
		} else {
			if (screen->interlace == 1) {
				reg_win_data->reg_area_data[0].c_offset =
				    uv_y_off * uv_stride * 2 +
				    uv_x_off * pixel_width / 8;
			} else {
				reg_win_data->reg_area_data[0].c_offset =
				    uv_y_off * uv_stride +
				    uv_x_off * pixel_width / 8;
			}
		}
	}
	return 0;
}

static int rk_fb_set_win_config(struct fb_info *info,
				struct rk_fb_win_cfg_data *win_data)
{
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct rk_fb_reg_data *regs;
#ifdef H_USE_FENCE
	struct sync_fence *release_fence[RK_MAX_BUF_NUM];
	struct sync_fence *retire_fence;
	struct sync_pt *release_sync_pt[RK_MAX_BUF_NUM];
	struct sync_pt *retire_sync_pt;
	char fence_name[20];
#endif
	int ret = 0, i, j = 0;
	int list_is_empty = 0;

	regs = kzalloc(sizeof(struct rk_fb_reg_data), GFP_KERNEL);
	if (!regs) {
		printk(KERN_INFO "could not allocate rk_fb_reg_data\n");
		ret = -ENOMEM;
		return ret;
	}

/*
	regs->post_cfg.xpos = win_data->post_cfg.xpos;
	regs->post_cfg.ypos = win_data->post_cfg.ypos;
	regs->post_cfg.xsize = win_data->post_cfg.xsize;
	regs->post_cfg.ysize = win_data->post_cfg.xsize;
*/
  	dev_drv->lcdc_win_num = 2;
  	mutex_lock(&dev_drv->win_config);
	for (i = 0; i < dev_drv->lcdc_win_num; i++) {
		if (win_data->win_par[i].win_id < dev_drv->lcdc_win_num) {
			rk_fb_set_win_buffer(info, &win_data->win_par[i],
					     &regs->reg_win_data[j]);
			if (regs->reg_win_data[j].area_num > 0) {
				regs->win_num++;
				regs->buf_num +=
				    regs->reg_win_data[j].area_buf_num;
			}
			j++;
		} else {
			printk(KERN_INFO "error:win_id bigger than lcdc_win_num\n");
			printk(KERN_INFO "i=%d,win_id=%d\n", i,
			       win_data->win_par[i].win_id);
		}
	}
	mutex_unlock(&dev_drv->win_config);
	mutex_lock(&dev_drv->output_lock);
	if (!(dev_drv->suspend_flag == 0)) {
		rk_fb_update_reg(dev_drv, regs);
		kfree(regs);
		printk(KERN_INFO "suspend_flag = 1\n");
		goto err;
	}

	dev_drv->timeline_max++;
#ifdef H_USE_FENCE
	for (i = 0; i < RK_MAX_BUF_NUM; i++) {
		if (i < regs->buf_num) {
			sprintf(fence_name, "fence%d", i);
			win_data->rel_fence_fd[i] = get_unused_fd();
			if (win_data->rel_fence_fd[i] < 0) {
				printk(KERN_INFO "rel_fence_fd=%d\n",
				       win_data->rel_fence_fd[i]);
				ret = -EFAULT;
				goto err;
			}
			release_sync_pt[i] =
			    sw_sync_pt_create(dev_drv->timeline,
					      dev_drv->timeline_max);
			release_fence[i] =
			    sync_fence_create(fence_name, release_sync_pt[i]);
			sync_fence_install(release_fence[i],
					   win_data->rel_fence_fd[i]);
		} else {
			win_data->rel_fence_fd[i] = -1;
		}
	}

	win_data->ret_fence_fd = get_unused_fd();
	if (win_data->ret_fence_fd < 0) {
		printk("ret_fence_fd=%d\n", win_data->ret_fence_fd);
		ret = -EFAULT;
		goto err;
	}
	retire_sync_pt =
	    sw_sync_pt_create(dev_drv->timeline, dev_drv->timeline_max);
	retire_fence = sync_fence_create("ret_fence", retire_sync_pt);
	sync_fence_install(retire_fence, win_data->ret_fence_fd);
#else
	for (i = 0; i < RK_MAX_BUF_NUM; i++)
		win_data->rel_fence_fd[i] = -1;

	win_data->ret_fence_fd = -1;
#endif
	if (dev_drv->wait_fs == 0) {
		mutex_lock(&dev_drv->update_regs_list_lock);
		list_add_tail(&regs->list, &dev_drv->update_regs_list);
		mutex_unlock(&dev_drv->update_regs_list_lock);
		queue_kthread_work(&dev_drv->update_regs_worker,
				   &dev_drv->update_regs_work);
	} else {
		mutex_lock(&dev_drv->update_regs_list_lock);
		list_is_empty = list_empty(&dev_drv->update_regs_list) &&
					list_empty(&dev_drv->saved_list);
		mutex_unlock(&dev_drv->update_regs_list_lock);
		if (!list_is_empty) {
			ret = wait_event_timeout(dev_drv->update_regs_wait,
				list_empty(&dev_drv->update_regs_list) && list_empty(&dev_drv->saved_list),
				msecs_to_jiffies(60));
			if (ret > 0)
				rk_fb_update_reg(dev_drv, regs);
			else
				printk("%s: wait update_regs_wait timeout\n", __func__);
		} else if (ret == 0) {
			rk_fb_update_reg(dev_drv, regs);
		}
		kfree(regs);
	}

err:
	mutex_unlock(&dev_drv->output_lock);
	return ret;
}

#if 1
static int cfgdone_distlist[10] = { 0 };

static int cfgdone_index;
static int cfgdone_lasttime;

int rk_get_real_fps(int before)
{
	struct timespec now;
	int dist_curr;
	int dist_total = 0;
	int dist_count = 0;
	int dist_first = 0;
	
	int index = cfgdone_index;
	int i = 0, fps = 0;
	int total;

	if (before > 100)
		before = 100;
	if (before < 0)
		before = 0;
	//box modified
	return 0;
	getnstimeofday(&now);
	dist_curr = (now.tv_sec * 1000000 + now.tv_nsec / 1000) -
			cfgdone_lasttime;
	total = dist_curr;
	/*
	   printk("fps: ");
	 */
	for (i = 0; i < 10; i++) {
		if (--index < 0)
			index = 9;
		total += cfgdone_distlist[index];
		if (i == 0)
			dist_first = cfgdone_distlist[index];
		if (total < (before * 1000)) {
			/*
			   printk("[%d:%d] ", dist_count, cfgdone_distlist[index]);
			 */
			dist_total += cfgdone_distlist[index];
			dist_count++;
		} else {
			break;
		}
	}

	/*
	   printk("total %d, count %d, curr %d, ", dist_total, dist_count, dist_curr);
	 */
	dist_curr = (dist_curr > dist_first) ? dist_curr : dist_first;
	dist_total += dist_curr;
	dist_count++;

	if (dist_total > 0)
		fps = (1000000 * dist_count) / dist_total;
	else
		fps = 60;

	/*
	   printk("curr2 %d, fps=%d\n", dist_curr, fps);
	 */
	return fps;
}
EXPORT_SYMBOL(rk_get_real_fps);

#endif
#ifdef CONFIG_ROCKCHIP_IOMMU
#define ION_MAX 10
static struct ion_handle *ion_hanle[ION_MAX];
#endif
static int rk_fb_ioctl(struct fb_info *info, unsigned int cmd,
		       unsigned long arg)
{
	struct rk_fb *rk_fb = dev_get_drvdata(info->device);
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct fb_fix_screeninfo *fix = &info->fix;
	struct rk_lcdc_win *win;
	int enable;	/* enable fb:1 enable;0 disable */
	int ovl;	/* overlay:0 win1 on the top of win0;1,win0 on the top of win1 */
	int num_buf;	/* buffer_number */
	int ret;
	struct rk_fb_win_cfg_data win_data;
	unsigned int dsp_addr[4];
	int list_stat;

	int win_id = dev_drv->ops->fb_get_win_id(dev_drv, info->fix.id);

	void __user *argp = (void __user *)arg;
	win = dev_drv->win[win_id];

	switch (cmd) {
	case RK_FBIOSET_YUV_ADDR:
		{
			u32 yuv_phy[2];

			if (copy_from_user(yuv_phy, argp, 8))
				return -EFAULT;
			#ifdef CONFIG_ROCKCHIP_IOMMU
			if (!dev_drv->iommu_enabled || !strcmp(info->fix.id, "fb0")) {
			#endif
				fix->smem_start = yuv_phy[0];
				fix->mmio_start = yuv_phy[1];
			#ifdef CONFIG_ROCKCHIP_IOMMU
			} else {
				int usr_fd, offset, tmp;
				struct ion_handle *hdl;
				ion_phys_addr_t phy_addr;
				size_t len;

				usr_fd = yuv_phy[0];
				offset = yuv_phy[1] - yuv_phy[0];

				if (!usr_fd) {
					fix->smem_start = 0;
					fix->mmio_start = 0;
					break;
				}

				if (ion_hanle[ION_MAX - 1] != 0) {
					/*ion_unmap_kernel(rk_fb->ion_client, ion_hanle[ION_MAX - 1]);*/
					/*ion_unmap_iommu(dev_drv->dev, rk_fb->ion_client, ion_hanle[ION_MAX - 1]);*/
					ion_free(rk_fb->ion_client, ion_hanle[ION_MAX - 1]);
					ion_hanle[ION_MAX - 1] = 0;
				}

				hdl = ion_import_dma_buf(rk_fb->ion_client, usr_fd);
				if (IS_ERR(hdl)) {
					dev_err(info->dev, "failed to get ion handle:%ld\n",
						PTR_ERR(hdl));
					return -EFAULT;
				}

				ret = ion_map_iommu(dev_drv->dev, rk_fb->ion_client, hdl,
							(unsigned long *)&phy_addr,
							(unsigned long *)&len);
				if (ret < 0) {
					dev_err(info->dev, "ion map to get phy addr failed");
					ion_free(rk_fb->ion_client, hdl);
					return -ENOMEM;
				}
				fix->smem_start = phy_addr;
				fix->mmio_start = phy_addr + offset;
				fix->smem_len = len;
				/*info->screen_base = ion_map_kernel(rk_fb->ion_client, hdl);*/

				ion_hanle[0] = hdl;
				for (tmp = ION_MAX - 1; tmp > 0; tmp--)
					ion_hanle[tmp] = ion_hanle[tmp - 1];
				ion_hanle[0] = 0;
			}
			#endif
			break;
		}
	case RK_FBIOSET_ENABLE:
		if (copy_from_user(&enable, argp, sizeof(enable)))
			return -EFAULT;
		dev_drv->win[win_id]->logicalstate = enable;
		if(dev_drv->enable)
			dev_drv->ops->open(dev_drv, win_id, enable);
		break;
	case RK_FBIOGET_ENABLE:
		enable = dev_drv->ops->get_win_state(dev_drv, win_id);
		if (copy_to_user(argp, &enable, sizeof(enable)))
			return -EFAULT;
		break;
	case RK_FBIOSET_OVERLAY_STA:
		if (copy_from_user(&ovl, argp, sizeof(ovl)))
			return -EFAULT;
		//dev_drv->ops->ovl_mgr(dev_drv, ovl, 1);
		break;
	case RK_FBIOGET_OVERLAY_STA:
		ovl = dev_drv->ops->ovl_mgr(dev_drv, 0, 0);
		if (copy_to_user(argp, &ovl, sizeof(ovl)))
			return -EFAULT;
		break;
	case RK_FBIOPUT_NUM_BUFFERS:
		if (copy_from_user(&num_buf, argp, sizeof(num_buf)))
			return -EFAULT;
		dev_drv->num_buf = num_buf;
		break;
	case RK_FBIOSET_VSYNC_ENABLE:
		if (copy_from_user(&enable, argp, sizeof(enable)))
			return -EFAULT;
		dev_drv->vsync_info.active = enable;
		break;

	case RK_FBIOGET_DSP_ADDR:
		dev_drv->ops->get_dsp_addr(dev_drv, dsp_addr);
		if (copy_to_user(argp, &dsp_addr, sizeof(dsp_addr)))
			return -EFAULT;
		break;
	case RK_FBIOGET_LIST_STA:
		list_stat = rk_fb_get_list_stat(dev_drv);
		if (copy_to_user(argp, &list_stat, sizeof(list_stat)))
			return -EFAULT;

		break;
	case RK_FBIOGET_IOMMU_STA:
		if (copy_to_user(argp, &dev_drv->iommu_enabled,
				 sizeof(dev_drv->iommu_enabled)))
			return -EFAULT;
		break;
#if defined(CONFIG_ION_ROCKCHIP)
	case RK_FBIOSET_DMABUF_FD:
		{
			int usr_fd;
			struct ion_handle *hdl;
			ion_phys_addr_t phy_addr;
			size_t len;
			if (copy_from_user(&usr_fd, argp, sizeof(usr_fd)))
				return -EFAULT;
			hdl = ion_import_dma_buf(rk_fb->ion_client, usr_fd);
			ion_phys(rk_fb->ion_client, hdl, &phy_addr, &len);
			fix->smem_start = phy_addr;
			break;
		}
	case RK_FBIOGET_DMABUF_FD:
		{
			int fd =
			    ion_share_dma_buf_fd(rk_fb->ion_client,
						 win->area[0].ion_hdl);
			if (fd < 0) {
				dev_err(info->dev,
					"ion_share_dma_buf_fd failed\n");
				return fd;
			}
			if (copy_to_user(argp, &fd, sizeof(fd)))
				return -EFAULT;
			break;
		}
#endif
	case RK_FBIOSET_CLEAR_FB:
		memset(info->screen_base, 0, get_fb_size());
		break;
	case RK_FBIOSET_CONFIG_DONE:
		{
			int curr = 0;
			struct timespec now;

			getnstimeofday(&now);
			curr = now.tv_sec * 1000000 + now.tv_nsec / 1000;
			cfgdone_distlist[cfgdone_index++] =
			    curr - cfgdone_lasttime;
		/*	
			   printk("%d", curr - cfgdone_lasttime);
		*/	 
			cfgdone_lasttime = curr;
			if (cfgdone_index >= 10)
				cfgdone_index = 0;
		}
		if (copy_from_user(&win_data,
				   (struct rk_fb_win_cfg_data __user *)argp,
				   sizeof(win_data))) {
			ret = -EFAULT;
			break;
		};
		dev_drv->config_done = 1;
		dev_drv->wait_fs = win_data.wait_fs;
		if (rk_fb_set_win_config(info,&win_data)) {
			pr_info("config done error\n");
			return -EFAULT;
		}
		if (copy_to_user((struct rk_fb_win_cfg_data __user *)arg,
				 &win_data, sizeof(win_data))) {
			ret = -EFAULT;
			break;
		}	
		memset(&win_data, 0, sizeof(struct rk_fb_win_cfg_data));
		break;
	default:
		dev_drv->ops->ioctl(dev_drv, cmd, arg, win_id);
		break;
	}

	return 0;
}

static int rk_fb_blank(int blank_mode, struct fb_info *info)
{
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct fb_fix_screeninfo *fix = &info->fix;
	int win_id;

	win_id = dev_drv->ops->fb_get_win_id(dev_drv, fix->id);
	if (win_id < 0)
		return  -ENODEV;
		
	dev_drv->ops->blank(dev_drv, win_id, blank_mode);
	return 0;
}

static int rk_fb_check_var(struct fb_var_screeninfo *var, struct fb_info *info)
{

	if ((0 == var->xres_virtual) || (0 == var->yres_virtual) ||
	    (0 == var->xres) || (0 == var->yres) || (var->xres < 16) ||
	    ((16 != var->bits_per_pixel) &&
	    (32 != var->bits_per_pixel) &&
	    (24 != var->bits_per_pixel))) {
		dev_err(info->dev, "%s check var fail 1:\n"
			"xres_vir:%d>>yres_vir:%d\n"
			"xres:%d>>yres:%d\n"
			"bits_per_pixel:%d\n",
			info->fix.id,
			var->xres_virtual,
			var->yres_virtual,
			var->xres, var->yres, var->bits_per_pixel);
		return -EINVAL;
	}

	if (((var->xoffset + var->xres) > var->xres_virtual) ||
	    ((var->yoffset + var->yres) > (var->yres_virtual))) {
		dev_err(info->dev, "%s check_var fail 2:\n"
			"xoffset:%d>>xres:%d>>xres_vir:%d\n"
			"yoffset:%d>>yres:%d>>yres_vir:%d\n",
			info->fix.id,
			var->xoffset,
			var->xres,
			var->xres_virtual,
			var->yoffset, var->yres, var->yres_virtual);
		return -EINVAL;
	}

	return 0;
}

static ssize_t rk_fb_read(struct fb_info *info, char __user *buf,
			  size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	u8 *buffer, *dst;
	u8 __iomem *src;
	int c, cnt = 0, err = 0;
	unsigned long total_size;
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct rk_lcdc_win *win = NULL;
	int win_id = 0;

	win_id = dev_drv->ops->fb_get_win_id(dev_drv, info->fix.id);
	if (win_id < 0)
		return -ENODEV;
	else
		win = dev_drv->win[win_id];

	/* only read the current frame buffer */
	if (win->format == RGB565)
		total_size = win->area[0].y_vir_stride * win->area[0].yact << 1;
	else if (win->format == YUV420) {
		total_size =
		    (win->area[0].y_vir_stride * win->area[0].yact * 6);
	} else
		total_size = win->area[0].y_vir_stride * win->area[0].yact << 2;

	if (p >= total_size)
		return 0;

	if (count >= total_size)
		count = total_size;

	if (count + p > total_size)
		count = total_size - p;

	buffer = kmalloc((count > PAGE_SIZE) ? PAGE_SIZE : count, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	src = (u8 __iomem *) (info->screen_base + p + win->area[0].y_offset);

	while (count) {
		c = (count > PAGE_SIZE) ? PAGE_SIZE : count;
		dst = buffer;
		fb_memcpy_fromfb(dst, src, c);
		dst += c;
		src += c;

		if (copy_to_user(buf, buffer, c)) {
			err = -EFAULT;
			break;
		}
		*ppos += c;
		buf += c;
		cnt += c;
		count -= c;
	}

	kfree(buffer);

	return (err) ? err : cnt;
}

static ssize_t rk_fb_write(struct fb_info *info, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	u8 *buffer, *src;
	u8 __iomem *dst;
	int c, cnt = 0, err = 0;
	unsigned long total_size;
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct rk_lcdc_win *win = NULL;
	int win_id = 0;

	win_id = dev_drv->ops->fb_get_win_id(dev_drv, info->fix.id);
	if (win_id < 0)
		return -ENODEV;
	else
		win = dev_drv->win[win_id];

	/* write the current frame buffer */
	if (win->format == RGB565)
		total_size = win->area[0].xact * win->area[0].yact << 1;
	else
		total_size = win->area[0].xact * win->area[0].yact << 2;

	if (p > total_size)
		return -EFBIG;

	if (count > total_size) {
		err = -EFBIG;
		count = total_size;
	}

	if (count + p > total_size) {
		if (!err)
			err = -ENOSPC;

		count = total_size - p;
	}

	buffer = kmalloc((count > PAGE_SIZE) ? PAGE_SIZE : count, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	dst = (u8 __iomem *) (info->screen_base + p + win->area[0].y_offset);

	while (count) {
		c = (count > PAGE_SIZE) ? PAGE_SIZE : count;
		src = buffer;

		if (copy_from_user(src, buf, c)) {
			err = -EFAULT;
			break;
		}

		fb_memcpy_tofb(dst, src, c);
		dst += c;
		src += c;
		*ppos += c;
		buf += c;
		cnt += c;
		count -= c;
	}

	kfree(buffer);

	return (cnt) ? cnt : err;

}

static int rk_fb_set_par(struct fb_info *info)
{
	struct fb_var_screeninfo *var = &info->var;
	struct fb_fix_screeninfo *fix = &info->fix;
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	struct rk_lcdc_win *win = NULL;
	struct rk_screen *screen = dev_drv->cur_screen;
	struct rk_screen screen_primary;
	int win_id = 0;
	u32 cblen = 0, crlen = 0;
	u16 xsize = 0, ysize = 0;	/* winx display window height/width --->LCDC_WINx_DSP_INFO */
	u32 xoffset = var->xoffset;	/* offset from virtual to visible */
	u32 yoffset = var->yoffset;
	u16 xpos = (var->nonstd >> 8) & 0xfff;	/*visiable pos in panel */
	u16 ypos = (var->nonstd >> 20) & 0xfff;
	u32 xvir = var->xres_virtual;
	u32 yvir = var->yres_virtual;
	u8 data_format = var->nonstd & 0xff;
	u8 fb_data_fmt;
	u8 pixel_width;
	u32 vir_width_bit;
	u32 stride, uv_stride;
	u32 stride_32bit_1;
	u32 stride_32bit_2;
	u16 uv_x_off, uv_y_off, uv_y_act;
	u8 is_pic_yuv = 0;
       //$_rbox_$_modify_$_qiuen for box
        int xres = 0;
        int yres = 0;
        if (!strcmp(info->fix.id, "fb1")){
           struct rk_fb *rk_fb =  platform_get_drvdata(fb_pdev);
	   struct fb_info *fbi = rk_fb->fb[0];
           xres = fbi->var.xres;
           yres = fbi->var.yres;
        } else {
           xres = var->xres;
           yres = var->yres;
        }
       //$_rbox_$_modify_$_qiuen end
	var->pixclock = dev_drv->pixclock;
	win_id = dev_drv->ops->fb_get_win_id(dev_drv, info->fix.id);
	if (win_id < 0)
		return -ENODEV;
	else
		win = dev_drv->win[win_id];
	
	/* if the application has specific the horizontal and vertical display size */
	if (var->grayscale >> 8) {
		xsize = (var->grayscale >> 8) & 0xfff;
		ysize = (var->grayscale >> 20) & 0xfff;
	} else {		/*ohterwise  full  screen display */
		xsize = screen->mode.xres;
		ysize = screen->mode.yres;
	}

	fb_data_fmt = rk_fb_data_fmt(data_format,var->bits_per_pixel);
	pixel_width = rk_fb_pixel_width(fb_data_fmt);
	if((fb_data_fmt == YUV420_A)||(fb_data_fmt == YUV422_A)||(fb_data_fmt == YUV444_A)){
		vir_width_bit = xvir * 8;
		stride_32bit_1 = xvir;
		stride_32bit_2 = xvir*2;
	}else{
		vir_width_bit = pixel_width * xvir;
		stride_32bit_1	= ((vir_width_bit   + 31 ) & (~31 ))/8; //pixel_width = byte_num *8
		stride_32bit_2	= ((vir_width_bit*2 + 31 ) & (~31 ))/8; //pixel_width = byte_num *8
	}
	switch (fb_data_fmt) {
	case YUV422:
	case YUV422_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_1 >> 1;
		uv_x_off = xoffset >> 1;
		uv_y_off = yoffset;
		fix->line_length = stride;
		cblen = crlen = (xvir * yvir) >> 1;
		uv_y_act = win->area[0].yact >> 1;
		break;
	case YUV420:		/* 420sp */
	case YUV420_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_1;
		uv_x_off = xoffset;
		uv_y_off = yoffset >> 1;
		fix->line_length = stride;
		cblen = crlen = (xvir * yvir) >> 2;
		uv_y_act = win->area[0].yact >> 1;
		break;
	case YUV444:
	case YUV444_A:
		is_pic_yuv = 1;
		stride = stride_32bit_1;
		uv_stride = stride_32bit_2;
		uv_x_off = xoffset * 2;
		uv_y_off = yoffset;
		fix->line_length = stride << 2;
		cblen = crlen = (xvir * yvir);
		uv_y_act = win->area[0].yact;
		break;
	default:
		stride = stride_32bit_1;	/* default rgb */
		fix->line_length = stride;
		break;
	}

	/* x y mirror ,jump line */
	if (screen->y_mirror == 1) {
		if (screen->interlace == 1) {
			win->area[0].y_offset = yoffset * stride * 2 +
			    ((win->area[0].yact - 1) * 2 + 1) * stride +
			    xoffset * pixel_width / 8;
		} else {
			win->area[0].y_offset = yoffset * stride +
			    (win->area[0].yact - 1) * stride +
			    xoffset * pixel_width / 8;
		}
	} else {
		if (screen->interlace == 1) {
			win->area[0].y_offset =
			    yoffset * stride * 2 + xoffset * pixel_width / 8;
		} else {
			win->area[0].y_offset =
			    yoffset * stride + xoffset * pixel_width / 8;
		}
	}
	if (is_pic_yuv == 1) {
		if (screen->y_mirror == 1) {
			if (screen->interlace == 1) {
				win->area[0].c_offset =
				    uv_y_off * uv_stride * 2 +
				    ((uv_y_act - 1) * 2 + 1) * uv_stride +
				    uv_x_off * pixel_width / 8;
			} else {
				win->area[0].c_offset = uv_y_off*uv_stride + 
								(uv_y_act - 1)*uv_stride +
								uv_x_off*pixel_width/8;
			}		
		} else {
			if (screen->interlace == 1) {
				win->area[0].c_offset =
				    uv_y_off * uv_stride * 2 +
				    uv_x_off * pixel_width / 8;
			} else {
				win->area[0].c_offset =
				    uv_y_off * uv_stride +
				    uv_x_off * pixel_width / 8;
			}
		}		
	}
	//$_rbox_$_modify_$_zhengyang for box
	rk_fb_get_prmry_screen(&screen_primary);
	win->format = fb_data_fmt;
	win->area[0].y_vir_stride = stride >> 2;
	win->area[0].uv_vir_stride = uv_stride >> 2;
	win->area[0].xpos = xpos*screen->mode.xres/xres;  //screen_primary.mode.xres;
	win->area[0].ypos = ypos*screen->mode.yres/yres;//screen_primary.mode.yres;
	win->area[0].xsize = screen->mode.xres*xsize/xres;//screen_primary.mode.xres;
	win->area[0].ysize = screen->mode.yres*ysize/yres;//screen_primary.mode.yres;
	//$_rbox_$_modify_$_zhengyang end
//	win->area[0].smem_start = fix->smem_start;
//	win->area[0].cbr_start = fix->smem_start+stride*yvir;//fix->mmio_start;
	win->area[0].xact = var->xres;	/* winx active window height,is a wint of vir */
	win->area[0].yact = var->yres;
	win->area[0].xvir = var->xres_virtual;	/* virtual resolution  stride --->LCDC_WINx_VIR */
	win->area[0].yvir = var->yres_virtual;
	win->area[0].state = 1;
	win->area_num = 1;
	win->alpha_mode = 4;	/* AB_SRC_OVER; */
	win->alpha_en = ((win->format == ARGB888)
			 || (win->format == ABGR888)) ? 1 : 0;
	win->g_alpha_val = 0;
        if (win->format == ARGB888||win->format == ABGR888) {
          win->z_order = 1;
        } else {
           win->z_order = 0;
        }
        dev_drv->ops->ovl_mgr(dev_drv, 0, 1);
        dev_drv->ops->cfg_done(dev_drv);

	if(info->var.activate & FB_ACTIVATE_FORCE)
		dev_drv->ops->set_par(dev_drv, win_id);

	return 0;
}

static inline unsigned int chan_to_field(unsigned int chan,
					 struct fb_bitfield *bf)
{
	chan &= 0xffff;
	chan >>= 16 - bf->length;
	return chan << bf->offset;
}

static int fb_setcolreg(unsigned regno,
			unsigned red, unsigned green, unsigned blue,
			unsigned transp, struct fb_info *info)
{
	unsigned int val;

	switch (info->fix.visual) {
	case FB_VISUAL_TRUECOLOR:
		/* true-colour, use pseudo-palette */
		if (regno < 16) {
			u32 *pal = info->pseudo_palette;
			val = chan_to_field(red, &info->var.red);
			val |= chan_to_field(green, &info->var.green);
			val |= chan_to_field(blue, &info->var.blue);
			pal[regno] = val;
		}
		break;
	default:
		return -1;	/* unknown type */
	}

	return 0;
}

static int rk_fb_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)info->par;
	int win_id = dev_drv->ops->fb_get_win_id(dev_drv, info->fix.id);
	struct rk_lcdc_win *win;
	win = dev_drv->win[win_id];

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return dma_buf_mmap(win->area[0].dma_buf, vma, 0);
}

static struct fb_ops fb_ops = {
	.owner = THIS_MODULE,
	.fb_open = rk_fb_open,
	.fb_release = rk_fb_close,
	.fb_check_var = rk_fb_check_var,
	.fb_set_par = rk_fb_set_par,
	.fb_blank = rk_fb_blank,
	.fb_ioctl = rk_fb_ioctl,
	.fb_pan_display = rk_fb_pan_display,
	.fb_read = rk_fb_read,
	.fb_write = rk_fb_write,
	.fb_setcolreg = fb_setcolreg,
	.fb_fillrect = cfb_fillrect,
	.fb_copyarea = cfb_copyarea,
	.fb_imageblit = cfb_imageblit,
};

static struct fb_var_screeninfo def_var = {
#if defined(CONFIG_LOGO_LINUX_BMP)
	.red = {16, 8, 0},
	.green = {8, 8, 0},
	.blue = {0, 8, 0},
	.transp = {0, 0, 0},
	.nonstd = HAL_PIXEL_FORMAT_BGRA_8888,
#else
	.red = {11, 5, 0},
	.green = {5, 6, 0},
	.blue = {0, 5, 0},
	.transp = {0, 0, 0},
	.nonstd = HAL_PIXEL_FORMAT_RGB_565,	/* (ypos<<20+xpos<<8+format) format */
#endif
	.grayscale = 0,		/* (ysize<<20+xsize<<8) */
	.activate = FB_ACTIVATE_NOW,
	.accel_flags = 0,
	.vmode = FB_VMODE_NONINTERLACED,
};

static struct fb_fix_screeninfo def_fix = {
	.type = FB_TYPE_PACKED_PIXELS,
	.type_aux = 0,
	.xpanstep = 1,
	.ypanstep = 1,
	.ywrapstep = 0,
	.accel = FB_ACCEL_NONE,
	.visual = FB_VISUAL_TRUECOLOR,

};


static int rk_fb_wait_for_vsync_thread(void *data)
{
	struct rk_lcdc_driver  *dev_drv = data;
	struct rk_fb *rk_fb =  platform_get_drvdata(fb_pdev);
	struct fb_info *fbi = rk_fb->fb[dev_drv->fb_index_base];

	while (!kthread_should_stop()) {
		ktime_t timestamp = dev_drv->vsync_info.timestamp;
		int ret = wait_event_interruptible(dev_drv->vsync_info.wait,
				!ktime_equal(timestamp, dev_drv->vsync_info.timestamp) &&
				(dev_drv->vsync_info.active || dev_drv->vsync_info.irq_stop));

		if (!ret)
			sysfs_notify(&fbi->dev->kobj, NULL, "vsync");
	}

	return 0;
}

static ssize_t rk_fb_vsync_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct fb_info *fbi = dev_get_drvdata(dev);
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)fbi->par;
	return scnprintf(buf, PAGE_SIZE, "%llu\n",
			 ktime_to_ns(dev_drv->vsync_info.timestamp));
}

static DEVICE_ATTR(vsync, S_IRUGO, rk_fb_vsync_show, NULL);

/*
 * this two function is for other module that in the kernel which
 * need show image directly through fb
 * fb_id:we have 4 fb here,default we use fb0 for ui display
 */
struct fb_info *rk_get_fb(int fb_id)
{
	struct rk_fb *inf = platform_get_drvdata(fb_pdev);
	struct fb_info *fb = inf->fb[fb_id];
	return fb;
}
EXPORT_SYMBOL(rk_get_fb);

void rk_direct_fb_show(struct fb_info *fbi)
{
	rk_fb_set_par(fbi);
	rk_fb_pan_display(&fbi->var, fbi);
}
EXPORT_SYMBOL(rk_direct_fb_show);

int rk_fb_dpi_open(bool open)
{
	struct rk_lcdc_driver *dev_drv = NULL;
	dev_drv = rk_get_prmry_lcdc_drv();
	dev_drv->ops->dpi_open(dev_drv, open);

	return 0;
}

int rk_fb_dpi_win_sel(int win_id)
{
	struct rk_lcdc_driver *dev_drv = NULL;
	dev_drv = rk_get_prmry_lcdc_drv();
	dev_drv->ops->dpi_win_sel(dev_drv, win_id);

	return 0;
}

int rk_fb_dpi_status(void)
{
	int ret;
	struct rk_lcdc_driver *dev_drv = NULL;
	dev_drv = rk_get_prmry_lcdc_drv();
	ret = dev_drv->ops->dpi_status(dev_drv);

	return ret;
}

/*
 *function:this function will be called by display device, enable/disable lcdc
 *screen: screen timing to be set to lcdc
 *enable: 0 disable lcdc; 1 enable lcdc; 2 just enable dclk
 *lcdc_id: the lcdc id the display device attached ,0 or 1
 */
int rk_fb_switch_screen(struct rk_screen *screen , int enable, int lcdc_id)
{
	struct rk_fb *rk_fb =  platform_get_drvdata(fb_pdev);
	struct fb_info *info = NULL;
	struct rk_lcdc_driver *dev_drv = NULL;
	char name[6];
	int i, win_id;
	
	if(screen == NULL)
		return -ENODEV;
	
	printk("\n%s lcdc_id %d type %d enable %d\n", __FUNCTION__, lcdc_id, screen->type, enable);
	
	sprintf(name, "lcdc%d",lcdc_id);
	for(i = 0; i < rk_fb->num_lcdc; i++) {
		if(!strcmp(rk_fb->lcdc_dev_drv[i]->name, name)) {
			dev_drv = rk_fb->lcdc_dev_drv[i];
			break;
		}
	}
	if(i == rk_fb->num_lcdc) {
		printk(KERN_ERR "%s driver not found!", name);
		return -ENODEV;
	}
	
	if(enable == 2 /*&& dev_drv->enable*/)
		return 0;
	
	if(!enable)
	{
		return 0;
		// if screen type is different, we do not disable lcdc.
		if( dev_drv->cur_screen->type != screen->type ||
		    rk_fb->num_lcdc < 2)
			return 0;
			
		for(i = 0; i < dev_drv->lcdc_win_num; i++) {
			//disable the layer which attached to this device
			if(dev_drv->win[i] && dev_drv->win[i]->state)
				dev_drv->ops->open(dev_drv, i, 0);
		}
		
		dev_drv->enable = enable;
		return 0;
	}
	else
		memcpy(dev_drv->cur_screen, screen, sizeof(struct rk_screen));
		
	dev_drv->enable = enable;

//	ret = dev_drv->ops->load_screen(dev_drv, 1);
//	
//	if(enable != 1)	return 0;
		
	for(i = 0; i < dev_drv->lcdc_win_num; i++) {
		#ifdef DUAL_LCDC_MAP_TO_SAME_FB
		info = rk_fb->fb[i];
		dev_drv1 = (struct rk_lcdc_driver *)info->par;
		if(dev_drv1 != dev_drv) {
			info->par = dev_drv;
//			dev_drv->overlay = dev_drv1->overlay;
			dev_drv->overscan = dev_drv1->overscan;
			dev_drv->vsync_info.active = dev_drv1->vsync_info.active;
		}
		memcpy(dev_drv->cur_screen, screen, sizeof(struct rk_screen));
		#else
		info = rk_fb->fb[dev_drv->fb_index_base + i];
		#endif
		win_id = dev_drv->ops->fb_get_win_id(dev_drv,info->fix.id);
//		printk("%s win id %d\n", info->fix.id, win_id);
		if(dev_drv->win[win_id]) {
			#ifdef DUAL_LCDC_MAP_TO_SAME_FB
			if(dev_drv1 && dev_drv1->win[win_id]) {
				dev_drv->win[win_id]->logicalstate = dev_drv1->win[win_id]->logicalstate;
				memcpy(dev_drv->win[win_id]->area, dev_drv1->win[win_id]->area, RK_WIN_MAX_AREA * sizeof(struct rk_lcdc_win_area));
//				dev_drv->win[win_id]->area[0] = dev_drv1->win[win_id]->area[0];
//				printk("%s win id %d state %d\n", info->fix.id, win_id, dev_drv->win[win_id]->logicalstate);
			}
			#endif
			printk("%s win id %d state %d\n", info->fix.id, win_id, dev_drv->win[win_id]->logicalstate);
			if( dev_drv->win[win_id]->logicalstate ) {
				dev_drv->ops->open(dev_drv, win_id, 1);
				if(win_id == 1) {
					mutex_lock(&dev_drv->win_config);
					dev_drv->ops->load_screen(dev_drv, 1);
					mutex_unlock(&dev_drv->win_config);
				}
				if (!dev_drv->config_done) {
					info->var.activate |= FB_ACTIVATE_FORCE;
					info->fbops->fb_set_par(info);
					info->fbops->fb_pan_display(&info->var, info);
				}
			}
//			else
//				dev_drv->ops->open(dev_drv, win_id, 0);
		}
	}
	printk("\n%s lcdc_id %d type %d enable %d done\n\n", __FUNCTION__, lcdc_id, screen->type, enable);
	return 0;
}

/*
 * function:this function current only called by hdmi for
 *	scale the display
 * scale_x: scale rate of x resolution
 * scale_y: scale rate of y resolution
 * lcdc_id: the lcdc id the hdmi attached ,0 or 1
 */
int rk_fb_disp_scale(u8 scale_x, u8 scale_y, u8 lcdc_id)
{
	return 0;
}

#if defined(CONFIG_ION_ROCKCHIP)
//leepe add
struct ion_handle *lcdc_handle;
//end
static int rk_fb_alloc_buffer_by_ion(struct fb_info *fbi,
				     struct rk_lcdc_win *win,
				     unsigned long fb_mem_size)
{
	struct rk_fb *rk_fb = platform_get_drvdata(fb_pdev);
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)fbi->par;
	struct ion_handle *handle;
	ion_phys_addr_t phy_addr;
	size_t len;
	int ret;

	if (dev_drv->iommu_enabled)
		handle = ion_alloc(rk_fb->ion_client, (size_t) fb_mem_size, 0,
				   ION_HEAP(ION_VMALLOC_HEAP_ID), 0);
	else
		handle = ion_alloc(rk_fb->ion_client, (size_t) fb_mem_size, 0,
				   ION_HEAP(ION_CMA_HEAP_ID), 0);
	if (IS_ERR(handle)) {
		dev_err(fbi->device, "failed to ion_alloc:%ld\n",
			PTR_ERR(handle));
		return -ENOMEM;
	}
	win->area[0].dma_buf = ion_share_dma_buf(rk_fb->ion_client, handle);
	if (IS_ERR_OR_NULL(win->area[0].dma_buf)) {
		printk("ion_share_dma_buf() failed\n");
		goto err_share_dma_buf;
	}
	win->area[0].ion_hdl = handle;
	//leepe add
	lcdc_handle = win->area[0].ion_hdl;
	//add end
	fbi->screen_base = ion_map_kernel(rk_fb->ion_client, handle);
#ifdef CONFIG_ROCKCHIP_IOMMU
	if (dev_drv->iommu_enabled)
		ret = ion_map_iommu(dev_drv->dev, rk_fb->ion_client, handle,
					(unsigned long *)&phy_addr,
					(unsigned long *)&len);
	else
		ret = ion_phys(rk_fb->ion_client, handle, &phy_addr, &len);
#else
	ret = ion_phys(rk_fb->ion_client, handle, &phy_addr, &len);
#endif
	if (ret < 0) {
		dev_err(fbi->dev, "ion map to get phy addr failed\n");
		goto err_share_dma_buf;
	}
	fbi->fix.smem_start = phy_addr;
	fbi->fix.smem_len = len;
	printk(KERN_INFO "alloc_buffer:ion_phy_addr=0x%lx\n", phy_addr);
	return 0;

err_share_dma_buf:
	ion_free(rk_fb->ion_client, handle);
	return -ENOMEM;
}
#endif

static int rk_fb_alloc_buffer(struct fb_info *fbi, int fb_id)
{
	struct rk_fb *rk_fb = platform_get_drvdata(fb_pdev);
	struct rk_lcdc_driver *dev_drv = (struct rk_lcdc_driver *)fbi->par;
	struct rk_lcdc_win *win = NULL;
	int win_id;
	int ret = 0;
	unsigned long fb_mem_size;
#if !defined(CONFIG_ION_ROCKCHIP)
	dma_addr_t fb_mem_phys;
	void *fb_mem_virt;
#endif

	win_id = dev_drv->ops->fb_get_win_id(dev_drv, fbi->fix.id);
	if (win_id < 0)
		return -ENODEV;
	else
		win = dev_drv->win[win_id];

	if (!strcmp(fbi->fix.id, "fb0")) {
		fb_mem_size = get_fb_size();
#if defined(CONFIG_ION_ROCKCHIP)
		if (rk_fb_alloc_buffer_by_ion(fbi, win, fb_mem_size) < 0)
			return -ENOMEM;
#else
		fb_mem_virt = dma_alloc_writecombine(fbi->dev, fb_mem_size,
						     &fb_mem_phys, GFP_KERNEL);
		if (!fb_mem_virt) {
			pr_err("%s: Failed to allocate framebuffer\n",
			       __func__);
			return -ENOMEM;
		}
		fbi->fix.smem_len = fb_mem_size;
		fbi->fix.smem_start = fb_mem_phys;
		fbi->screen_base = fb_mem_virt;
#endif
		memset(fbi->screen_base, 0, fbi->fix.smem_len);
		printk(KERN_INFO "fb%d:phy:%lx>>vir:%p>>len:0x%x\n", fb_id,
		       fbi->fix.smem_start, fbi->screen_base,
		       fbi->fix.smem_len);
	} else {
		if (dev_drv->rotate_mode > X_Y_MIRROR) {
			fb_mem_size = get_fb_size();
#if defined(CONFIG_ION_ROCKCHIP)
			if (rk_fb_alloc_buffer_by_ion(fbi, win, fb_mem_size) < 0)
				return -ENOMEM;
#else
			fb_mem_virt = dma_alloc_writecombine(fbi->dev,
					fb_mem_size, &fb_mem_phys, GFP_KERNEL);
			if (!fb_mem_virt) {
				pr_err("%s: Failed to allocate framebuffer\n",
					__func__);
				return -ENOMEM;
			}
			fbi->fix.smem_len = fb_mem_size;
			fbi->fix.smem_start = fb_mem_phys;
			fbi->screen_base = fb_mem_virt;
#endif
		} else {
		//leepe add 
			ion_phys_addr_t phy_addr;
			size_t len;
			int ret;
#ifdef CONFIG_ROCKCHIP_IOMMU
			if (dev_drv->iommu_enabled)
				ret = ion_map_iommu(dev_drv->dev, rk_fb->ion_client, lcdc_handle,
							(unsigned long *)&phy_addr,
							(unsigned long *)&len);
			else
				ret = ion_phys(rk_fb->ion_client, lcdc_handle, &phy_addr, &len);
#else
			ret = ion_phys(rk_fb->ion_client, lcdc_handle, &phy_addr, &len);
#endif
			if (ret < 0) {
				dev_err(fbi->dev, "ion map to get phy addr failed\n");
			}
			
			fbi->fix.smem_start = rk_fb->fb[0]->fix.smem_start;
			fbi->fix.smem_len = rk_fb->fb[0]->fix.smem_len;
			fbi->screen_base = rk_fb->fb[0]->screen_base;
		}

		printk(KERN_INFO "fb%d:phy:%lx>>vir:%p>>len:0x%x\n", fb_id,
		       fbi->fix.smem_start, fbi->screen_base,
		       fbi->fix.smem_len);
	}

	fbi->screen_size = fbi->fix.smem_len;
	win_id = dev_drv->ops->fb_get_win_id(dev_drv, fbi->fix.id);
	if (win_id >= 0) {
		win = dev_drv->win[win_id];
		win->reserved = fbi->fix.smem_start;
	}

	return ret;
}

#if 0
static int rk_release_fb_buffer(struct fb_info *fbi)
{
	/* buffer for fb1 and fb3 are alloc by android */
	if (!strcmp(fbi->fix.id, "fb1") || !strcmp(fbi->fix.id, "fb3"))
		return 0;
	iounmap(fbi->screen_base);
	release_mem_region(fbi->fix.smem_start, fbi->fix.smem_len);
	return 0;

}
#endif

static int init_lcdc_win(struct rk_lcdc_driver *dev_drv,
			 struct rk_lcdc_win *def_win)
{
	int i;
	int lcdc_win_num = dev_drv->lcdc_win_num;
	for (i = 0; i < lcdc_win_num; i++) {
		struct rk_lcdc_win *win = NULL;
		win = kzalloc(sizeof(struct rk_lcdc_win), GFP_KERNEL);
		if (!win) {
			dev_err(dev_drv->dev, "kzmalloc for win fail!");
			return -ENOMEM;
		}

		strcpy(win->name, def_win[i].name);
		win->id = def_win[i].id;
		win->support_3d = def_win[i].support_3d;
		dev_drv->win[i] = win;
	}

	return 0;
}

static int init_lcdc_device_driver(struct rk_fb *rk_fb,
				   struct rk_lcdc_win *def_win, int index)
{
	struct rk_lcdc_driver *dev_drv = rk_fb->lcdc_dev_drv[index];
	struct rk_screen *screen = devm_kzalloc(dev_drv->dev,
						sizeof(struct rk_screen),
						GFP_KERNEL);
	if (!screen) {
		dev_err(dev_drv->dev, "malloc screen for lcdc%d fail!",
			dev_drv->id);
		return -ENOMEM;
	}

	screen->screen_id = 0;
	screen->lcdc_id = dev_drv->id;
	screen->overscan.left = 100;
	screen->overscan.top = 100;
	screen->overscan.right = 100;
	screen->overscan.bottom = 100;

	screen->x_mirror = dev_drv->rotate_mode & X_MIRROR;
	screen->y_mirror = dev_drv->rotate_mode & Y_MIRROR;

	dev_drv->screen0 = screen;
	dev_drv->cur_screen = screen;
	sprintf(dev_drv->name, "lcdc%d", dev_drv->id);
	init_lcdc_win(dev_drv, def_win);
	init_completion(&dev_drv->frame_done);
	spin_lock_init(&dev_drv->cpl_lock);
	mutex_init(&dev_drv->win_config);
	mutex_init(&dev_drv->fb_win_id_mutex);
	mutex_init(&dev_drv->front_lock);
//	dev_drv->ops->fb_win_remap(dev_drv, FB_DEFAULT_ORDER);
	dev_drv->ops->fb_win_remap(dev_drv, FB0_WIN1_FB1_WIN0_FB2_WIN2_FB3_WIN3_FB4_HWC);
	dev_drv->first_frame = 1;
	dev_drv->overscan.left = 100;
	dev_drv->overscan.top = 100;
	dev_drv->overscan.right = 100;
	dev_drv->overscan.bottom = 100;
	rk_disp_pwr_ctr_parse_dt(dev_drv);
	if (dev_drv->prop == PRMRY) {
		if(dev_drv->ops->set_dsp_cabc)
			dev_drv->ops->set_dsp_cabc(dev_drv, dev_drv->cabc_mode);
		rk_fb_set_prmry_screen(screen);
	}
	rk_fb_get_prmry_screen(screen);
	dev_drv->trsm_ops = rk_fb_trsm_ops_get(screen->type);

	return 0;
}

#ifdef CONFIG_LOGO_LINUX_BMP
static struct linux_logo *bmp_logo;
static int fb_prewine_bmp_logo(struct fb_info *info, int rotate)
{
	bmp_logo = fb_find_logo(24);
	if (bmp_logo == NULL) {
		printk(KERN_INFO "%s error\n", __func__);
		return 0;
	}
	return 1;
}

static void fb_show_bmp_logo(struct fb_info *info, int rotate)
{
	unsigned char *src = bmp_logo->data;
	unsigned char *dst = info->screen_base;
	int i;
	unsigned int Needwidth = (*(src - 24) << 8) | (*(src - 23));
	unsigned int Needheight = (*(src - 22) << 8) | (*(src - 21));

	for (i = 0; i < Needheight; i++)
		memcpy(dst + info->var.xres * i * 4,
		       src + bmp_logo->width * i * 4, Needwidth * 4);

}
#endif

/*
 * check if the primary lcdc has registerd,
 * the primary lcdc mas register first
 */
bool is_prmry_rk_lcdc_registered(void)
{
	struct rk_fb *rk_fb = platform_get_drvdata(fb_pdev);
	if (rk_fb->lcdc_dev_drv[0])
		return true;
	else
		return false;

}

int rk_fb_register(struct rk_lcdc_driver *dev_drv,
		   struct rk_lcdc_win *win, int id)
{
	struct rk_fb *rk_fb = platform_get_drvdata(fb_pdev);
	struct fb_info *fbi;
	int i = 0, ret = 0, index = 0;
//#if defined(CONFIG_ROCKCHIP_IOMMU)
//	struct device *mmu_dev = NULL;
//#endif
	if (rk_fb->num_lcdc == RK30_MAX_LCDC_SUPPORT)
		return -ENXIO;

	for (i = 0; i < RK30_MAX_LCDC_SUPPORT; i++) {
		if (!rk_fb->lcdc_dev_drv[i]) {
			rk_fb->lcdc_dev_drv[i] = dev_drv;
			rk_fb->lcdc_dev_drv[i]->id = id;
			rk_fb->num_lcdc++;
			break;
		}
	}

	index = i;
	init_lcdc_device_driver(rk_fb, win, index);
	dev_drv->fb_index_base = rk_fb->num_fb;
	for (i = 0; i < dev_drv->lcdc_win_num; i++) {
		fbi = framebuffer_alloc(0, &fb_pdev->dev);
		if (!fbi) {
			dev_err(&fb_pdev->dev, "fb framebuffer_alloc fail!");
			ret = -ENOMEM;
		}
		fbi->par = dev_drv;
		fbi->var = def_var;
		fbi->fix = def_fix;
		sprintf(fbi->fix.id, "fb%d", rk_fb->num_fb);
		fb_videomode_to_var(&fbi->var, &dev_drv->cur_screen->mode);
		fbi->var.grayscale |=
		    (fbi->var.xres << 8) + (fbi->var.yres << 20);
#if defined(CONFIG_LOGO_LINUX_BMP)
		fbi->var.bits_per_pixel = 32;
#else
		fbi->var.bits_per_pixel = 16;
#endif
		fbi->fix.line_length =
		    (fbi->var.xres_virtual) * (fbi->var.bits_per_pixel >> 3);
		fbi->var.width = dev_drv->cur_screen->width;
		fbi->var.height = dev_drv->cur_screen->height;
		fbi->var.pixclock = dev_drv->pixclock;
		if (dev_drv->iommu_enabled)
			fb_ops.fb_mmap = rk_fb_mmap;
		fbi->fbops = &fb_ops;
		fbi->flags = FBINFO_FLAG_DEFAULT;
		fbi->pseudo_palette = dev_drv->win[i]->pseudo_pal;
		ret = register_framebuffer(fbi);
		if (ret < 0) {
			dev_err(&fb_pdev->dev,
				"%s fb%d register_framebuffer fail!\n",
				__func__, rk_fb->num_fb);
			return ret;
		}
		rkfb_create_sysfs(fbi);
		rk_fb->fb[rk_fb->num_fb] = fbi;
		dev_info(fbi->dev, "rockchip framebuffer registerd:%s\n",
			 fbi->fix.id);
		rk_fb->num_fb++;

		if (i == 0) {
			init_waitqueue_head(&dev_drv->vsync_info.wait);
			init_waitqueue_head(&dev_drv->update_regs_wait);
			ret = device_create_file(fbi->dev, &dev_attr_vsync);
			if (ret)
				dev_err(fbi->dev,
					"failed to create vsync file\n");
			dev_drv->vsync_info.thread =
			    kthread_run(rk_fb_wait_for_vsync_thread, dev_drv,
					"fb-vsync");
			if (dev_drv->vsync_info.thread == ERR_PTR(-ENOMEM)) {
				dev_err(fbi->dev,
					"failed to run vsync thread\n");
				dev_drv->vsync_info.thread = NULL;
			}
			dev_drv->vsync_info.active = 1;

			mutex_init(&dev_drv->output_lock);

			INIT_LIST_HEAD(&dev_drv->update_regs_list);
			mutex_init(&dev_drv->update_regs_list_lock);
			init_kthread_worker(&dev_drv->update_regs_worker);

			dev_drv->update_regs_thread =
			    kthread_run(kthread_worker_fn,
					&dev_drv->update_regs_worker, "rk-fb");
			if (IS_ERR(dev_drv->update_regs_thread)) {
				int err = PTR_ERR(dev_drv->update_regs_thread);
				dev_drv->update_regs_thread = NULL;

				printk("failed to run update_regs thread\n");
				return err;
			}
			init_kthread_work(&dev_drv->update_regs_work,
					  rk_fb_update_regs_handler);

			dev_drv->timeline =
			    sw_sync_timeline_create("fb-timeline");
			dev_drv->timeline_max = 1;
		}

	}

	/* show logo for primary display device */
// #if !defined(CONFIG_FRAMEBUFFER_CONSOLE) && defined(CONFIG_LOGO)
#if defined(CONFIG_LOGO)
	if (dev_drv->prop == PRMRY) {
		struct fb_info *main_fbi = rk_fb->fb[0];
	main_fbi->fbops->fb_open(main_fbi, 2);
//#if defined(CONFIG_ROCKCHIP_IOMMU)
//	if (dev_drv->iommu_enabled) {/* only alloc memory for main fb*/	
//		mmu_dev = rockchip_get_sysmmu_device_by_compatible(dev_drv->mmu_dts_name);
//		if (mmu_dev) {
//			platform_set_sysmmu(mmu_dev, dev_drv->dev);
//			/*rockchip_sysmmu_set_fault_handler(dev_drv->dev,
//					rk_fb_sysmmu_fault_handler);*/
//			iovmm_activate(dev_drv->dev);
//		}
//		else
//			dev_err(dev_drv->dev, "failed to get rockchip iommu device\n");
//	}
//#endif
		rk_fb_alloc_buffer(main_fbi, 0);	/* only alloc memory for main fb */
		if (support_uboot_display()) {
			if (dev_drv->iommu_enabled) {
				rk_fb_copy_from_loader(main_fbi);
				dev_drv->ops->direct_set_addr(dev_drv, 0,
							      main_fbi->fix.smem_start);
			}
			return 0;
		}
		main_fbi->fbops->fb_set_par(main_fbi);
#if  defined(CONFIG_LOGO_LINUX_BMP)
		if (fb_prewine_bmp_logo(main_fbi, FB_ROTATE_UR)) {
			fb_set_cmap(&main_fbi->cmap, main_fbi);
			fb_show_bmp_logo(main_fbi, FB_ROTATE_UR);
		}
#else
		if (fb_prepare_logo(main_fbi, FB_ROTATE_UR)) {
			fb_set_cmap(&main_fbi->cmap, main_fbi);
			fb_show_logo(main_fbi, FB_ROTATE_UR);
		}
#endif
		main_fbi->fbops->fb_pan_display(&main_fbi->var, main_fbi);
	} else {
//leepe mod
//#if !defined(CONFIG_ROCKCHIP_IOMMU)
#if defined(CONFIG_ROCKCHIP_IOMMU)
		struct fb_info *extend_fbi = rk_fb->fb[rk_fb->num_fb >> 1];
		//int extend_fb_id = get_extend_fb_id(extend_fbi);
		//rk_fb_alloc_buffer(extend_fbi, extend_fb_id);
		extend_fbi->fbops->fb_open(extend_fbi, 2);
		rk_fb_alloc_buffer(extend_fbi, 5);
		extend_fbi->var.activate |= FB_ACTIVATE_FORCE;
		extend_fbi->fbops->fb_set_par(extend_fbi);
		extend_fbi->fbops->fb_pan_display(&extend_fbi->var, extend_fbi);
#endif
	}
#endif
	return 0;


}

int rk_fb_unregister(struct rk_lcdc_driver *dev_drv)
{

	struct rk_fb *fb_inf = platform_get_drvdata(fb_pdev);
	struct fb_info *fbi;
	int fb_index_base = dev_drv->fb_index_base;
	int fb_num = dev_drv->lcdc_win_num;
	int i = 0;

	if (fb_inf->lcdc_dev_drv[i]->vsync_info.thread) {
		fb_inf->lcdc_dev_drv[i]->vsync_info.irq_stop = 1;
		kthread_stop(fb_inf->lcdc_dev_drv[i]->vsync_info.thread);
	}

	for (i = 0; i < fb_num; i++)
		kfree(dev_drv->win[i]);

	for (i = fb_index_base; i < (fb_index_base + fb_num); i++) {
		fbi = fb_inf->fb[i];
		unregister_framebuffer(fbi);
		/* rk_release_fb_buffer(fbi); */
		framebuffer_release(fbi);
	}
	fb_inf->lcdc_dev_drv[dev_drv->id] = NULL;
	fb_inf->num_lcdc--;

	return 0;
}

static int rk_fb_probe(struct platform_device *pdev)
{
	struct rk_fb *rk_fb = NULL;
	struct device_node *np = pdev->dev.of_node;
	u32 mode;

	if (!np) {
		dev_err(&pdev->dev, "Missing device tree node.\n");
		return -EINVAL;
	}

	rk_fb = devm_kzalloc(&pdev->dev, sizeof(struct rk_fb), GFP_KERNEL);
	if (!rk_fb) {
		dev_err(&pdev->dev, "kmalloc for rk fb fail!");
		return -ENOMEM;
	}
	platform_set_drvdata(pdev, rk_fb);

	if (!of_property_read_u32(np, "rockchip,disp-mode", &mode)) {
		rk_fb->disp_mode = mode;

	} else {
		dev_err(&pdev->dev, "no disp-mode node found!");
		return -ENODEV;
	}

	if (!of_property_read_u32(np, "rockchip,uboot-logo-on", &uboot_logo_on))
		printk("uboot-logo-on:%d\n", uboot_logo_on);

	dev_set_name(&pdev->dev, "rockchip-fb");
#if defined(CONFIG_ION_ROCKCHIP)
	rk_fb->ion_client = rockchip_ion_client_create("rk_fb");
	if (IS_ERR(rk_fb->ion_client)) {
		dev_err(&pdev->dev, "failed to create ion client for rk fb");
		return PTR_ERR(rk_fb->ion_client);
	} else {
		dev_info(&pdev->dev, "rk fb ion client create success!\n");
	}
#endif

	fb_pdev = pdev;
	dev_info(&pdev->dev, "rockchip framebuffer driver probe\n");
	return 0;
}

static int rk_fb_remove(struct platform_device *pdev)
{
	struct rk_fb *rk_fb = platform_get_drvdata(pdev);
	kfree(rk_fb);
	platform_set_drvdata(pdev, NULL);
	return 0;
}

static void rk_fb_shutdown(struct platform_device *pdev)
{
	struct rk_fb *rk_fb = platform_get_drvdata(pdev);
	int i;
	for (i = 0; i < rk_fb->num_lcdc; i++) {
		if (!rk_fb->lcdc_dev_drv[i])
			continue;

	}

}

static const struct of_device_id rkfb_dt_ids[] = {
	{.compatible = "rockchip,rk-fb",},
	{}
};

static struct platform_driver rk_fb_driver = {
	.probe = rk_fb_probe,
	.remove = rk_fb_remove,
	.driver = {
		   .name = "rk-fb",
		   .owner = THIS_MODULE,
		   .of_match_table = of_match_ptr(rkfb_dt_ids),
		   },
	.shutdown = rk_fb_shutdown,
};

static int __init rk_fb_init(void)
{
	return platform_driver_register(&rk_fb_driver);
}

static void __exit rk_fb_exit(void)
{
	platform_driver_unregister(&rk_fb_driver);
}

fs_initcall(rk_fb_init);
module_exit(rk_fb_exit);
