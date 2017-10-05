#include <linux/slab.h>
#include <asm/io.h>
#include <linux/rockchip/cpu.h>

#include "clk-ops.h"
#include "clk-pll.h"


static const struct pll_clk_set rk3188_pll_com_table[] = {
	_RK3188_PLL_SET_CLKS(1250000,	12,	625,	1),
	_RK3188_PLL_SET_CLKS(1200000,	1,	50,	1),
	_RK3188_PLL_SET_CLKS(1188000,	2,	99,	1),
	_RK3188_PLL_SET_CLKS(891000,	8,	594,	2),
	_RK3188_PLL_SET_CLKS(768000,	1,	64,	2),
	_RK3188_PLL_SET_CLKS(594000,	2,	198,	4),
	_RK3188_PLL_SET_CLKS(500000,	3,	250,	4),
	_RK3188_PLL_SET_CLKS(408000,	1,	68,	4),
	_RK3188_PLL_SET_CLKS(396000,	1,	66,	4),
	_RK3188_PLL_SET_CLKS(384000,	2,	128,	4),
	_RK3188_PLL_SET_CLKS(360000,	1,	60,	4),
	_RK3188_PLL_SET_CLKS(300000,	1,	50,	4),
	_RK3188_PLL_SET_CLKS(297000,	2,	198,	8),
	_RK3188_PLL_SET_CLKS(148500,	2,	99,	8),
	_RK3188_PLL_SET_CLKS(0,		0,	0,	0),
};

static const struct pll_clk_set rk3188plus_pll_com_table[] = {
	_RK3188PLUS_PLL_SET_CLKS(1250000,	12,	625,	1),
	_RK3188PLUS_PLL_SET_CLKS(1200000,	1,	50,	1),
	_RK3188PLUS_PLL_SET_CLKS(1188000,	2,	99,	1),
	_RK3188PLUS_PLL_SET_CLKS(891000,	8,	594,	2),
	_RK3188PLUS_PLL_SET_CLKS(768000,	1,	64,	2),
	_RK3188PLUS_PLL_SET_CLKS(594000,	2,	198,	4),
	_RK3188PLUS_PLL_SET_CLKS(500000,	3,	250,	4),
	_RK3188PLUS_PLL_SET_CLKS(408000,	1,	68,	4),
	_RK3188PLUS_PLL_SET_CLKS(396000,	1,	66,	4),
	_RK3188PLUS_PLL_SET_CLKS(384000,	2,	128,	4),
	_RK3188PLUS_PLL_SET_CLKS(360000,	1,	60,	4),
	_RK3188PLUS_PLL_SET_CLKS(300000,	1,	50,	4),
	_RK3188PLUS_PLL_SET_CLKS(297000,	2,	198,	8),
	_RK3188PLUS_PLL_SET_CLKS(148500,	2,	99,	8),
	_RK3188PLUS_PLL_SET_CLKS(0,		0,	0,	0),
};

static const struct apll_clk_set rk3188_apll_table[] = {
	//            (_mhz,	nr,	nf,	no,	_periph_div,	_aclk_div)
	_RK3188_APLL_SET_CLKS(2208, 	1, 	92,	1, 	8,	81),
	_RK3188_APLL_SET_CLKS(2184,	1,	91,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(2160,	1,	90,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(2136,	1,	89,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(2112,	1,	88,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(2088,	1,	87,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(2064,	1,	86,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(2040,	1,	85,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(2016,	1,	84,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1992,	1,	83,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1968,	1,	82,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1944,	1,	81,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1920,	1,	80,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1896,	1,	79,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1872,	1,	78,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1848,	1,	77,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1824,	1,	76,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1800,	1,	75,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1776,	1,	74,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1752,	1,	73,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1728,	1,	72,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1704,	1,	71,	1,	8,	81),
	_RK3188_APLL_SET_CLKS(1680,	1,	70,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1656,	1,	69,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1632,	1,	68,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1608,	1,	67,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1560,	1,	65,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1512,	1,	63,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1488,	1,	62,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1464,	1,	61,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1440,	1,	60,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1416,	1,	59,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1392,	1,	58,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1368,	1,	57,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1344,	1,	56,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1320,	1,	55,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1296,	1,	54,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1272,	1,	53,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1248,	1,	52,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1224,	1,	51,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1200,	1,	50,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1176,	1,	49,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1128,	1,	47,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1104,	1,	46,	1,	8,	41),
	_RK3188_APLL_SET_CLKS(1008,	1,	84,	2,	8,	41),
	_RK3188_APLL_SET_CLKS(912, 	1,	76,	2,	8,	41),
	_RK3188_APLL_SET_CLKS(888, 	1,	74,	2,	8,	41),
	_RK3188_APLL_SET_CLKS(816,	1,	68,	2,	8,	41),
	_RK3188_APLL_SET_CLKS(792,	1,	66,	2,	8,	41),
	_RK3188_APLL_SET_CLKS(696,	1,	58,	2,	8,	41),
	_RK3188_APLL_SET_CLKS(600,	1,	50,	2,	4,	41),
	_RK3188_APLL_SET_CLKS(552,	1,	92,	4,	4,	41),
	_RK3188_APLL_SET_CLKS(504,	1,	84,	4,	4,	41),
	_RK3188_APLL_SET_CLKS(408,	1,	68,	4,	4,	21),
	_RK3188_APLL_SET_CLKS(312,	1,	52,	4,	2,	21),
	_RK3188_APLL_SET_CLKS(252,	1,	84,	8,	2,	21),
	_RK3188_APLL_SET_CLKS(216,	1,	72,	8,	2,	21),
	_RK3188_APLL_SET_CLKS(126,	1,	84,	16,	2,	11),
	_RK3188_APLL_SET_CLKS(48,  	1,	32,	16,	2,	11),
	_RK3188_APLL_SET_CLKS(0,	1,	32,	16,	2,	11),
};

static const struct apll_clk_set rk3288_apll_table[] = {
	//       	     (_mhz,	nr,	nf,	no,	l2ram,	m0,	mp,	atclk,	pclk_dbg)
	_RK3288_APLL_SET_CLKS(2208, 	1, 	92,	1, 	2,	2,	4,	4,	4),
	_RK3288_APLL_SET_CLKS(2184,	1,	91,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(2160,	1,	90,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(2136,	1,	89,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(2112,	1,	88,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(2088,	1,	87,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(2064,	1,	86,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(2040,	1,	85,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(2016,	1,	84,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1992,	1,	83,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1968,	1,	82,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1944,	1,	81,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1920,	1,	80,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1896,	1,	79,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1872,	1,	78,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1848,	1,	77,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1824,	1,	76,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1800,	1,	75,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1776,	1,	74,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1752,	1,	73,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1728,	1,	72,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1704,	1,	71,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1680,	1,	70,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1656,	1,	69,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1632,	1,	68,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1608,	1,	67,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1560,	1,	65,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1512,	1,	63,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1488,	1,	62,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1464,	1,	61,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1440,	1,	60,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1416,	1,	59,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1392,	1,	58,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1368,	1,	57,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1344,	1,	56,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1320,	1,	55,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1296,	1,	54,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1272,	1,	53,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1248,	1,	52,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1224,	1,	51,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1200,	1,	50,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1176,	1,	49,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1128,	1,	47,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1104,	1,	46,	1,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(1008,	1,	84,	2,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(912, 	1,	76,	2,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(888, 	1,	74,	2,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(816,	1,	68,	2,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(792,	1,	66,	2,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(696,	1,	58,	2,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(600,	1,	50,	2,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(552,	1,	92,	4,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(504,	1,	84,	4,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(408,	1,	68,	4,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(312,	1,	52,	4,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(252,	1,	84,	8,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(216,	1,	72,	8,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(126,	2,	84,	8,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(48,  	2,	32,	8,	2,      2,      4,      4,      4),
	_RK3288_APLL_SET_CLKS(0,	1,	32,	16,	2,      2,      4,      4,      4),
};

static void pll_wait_lock(struct clk_hw *hw)
{
	struct clk_pll *pll = to_clk_pll(hw);
	int delay = 24000000;


	while (delay > 0) {
		if (grf_readl(pll->status_offset) & (1 << pll->status_shift))
			break;
		delay--;
	}

	if (delay == 0) {
		clk_err("pll %s: can't lock! status_shift=%u\n"
				"pll_con0=%08x\npll_con1=%08x\n"
				"pll_con2=%08x\npll_con3=%08x\n",
				__clk_get_name(hw->clk),
				pll->status_shift,
				cru_readl(pll->reg + RK3188_PLL_CON(0)),
				cru_readl(pll->reg + RK3188_PLL_CON(1)),
				cru_readl(pll->reg + RK3188_PLL_CON(2)),
				cru_readl(pll->reg + RK3188_PLL_CON(3)));

		while(1);
	}
}

/* get rate that is most close to target */
static const struct apll_clk_set *apll_get_best_set(unsigned long rate,
		const struct apll_clk_set *table)
{
	const struct apll_clk_set *ps, *pt;

	ps = pt = table;
	while (pt->rate) {
		if (pt->rate == rate) {
			ps = pt;
			break;
		}

		if ((pt->rate > rate || (rate - pt->rate < ps->rate - rate)))
			ps = pt;
		if (pt->rate < rate)
			break;
		pt++;
	}

	return ps;
}

/* get rate that is most close to target */
static const struct pll_clk_set *pll_com_get_best_set(unsigned long rate,
		const struct pll_clk_set *table)
{
	const struct pll_clk_set *ps, *pt;

	ps = pt = table;
	while (pt->rate) {
		if (pt->rate == rate) {
			ps = pt;
			break;
		}

		if ((pt->rate > rate || (rate - pt->rate < ps->rate - rate)))
			ps = pt;
		if (pt->rate < rate)
			break;
		pt++;
	}

	return ps;
}

/* CLK_PLL_3188 type ops */
static unsigned long clk_pll_recalc_rate_3188(struct clk_hw *hw,
		unsigned long parent_rate)
{
	struct clk_pll *pll = to_clk_pll(hw);
	unsigned long rate;


	if (_RK3188_PLL_MODE_IS_NORM(pll->mode_offset, pll->mode_shift)) {
		u32 pll_con0 = cru_readl(pll->reg + RK3188_PLL_CON(0));
		u32 pll_con1 = cru_readl(pll->reg + RK3188_PLL_CON(1));

		u64 rate64 = (u64)parent_rate * RK3188_PLL_NF(pll_con1);

		do_div(rate64, RK3188_PLL_NR(pll_con0));
		do_div(rate64, RK3188_PLL_NO(pll_con0));

		rate = rate64;
	} else {
		/*FIXME*/
		rate = parent_rate;
		clk_debug("pll %s is in slow mode\n", __clk_get_name(hw->clk));
	}

	clk_debug("pll %s recalc rate =%lu\n", __clk_get_name(hw->clk), rate);

	return rate;
}

static long clk_pll_round_rate_3188(struct clk_hw *hw, unsigned long rate,
		unsigned long *prate)
{
	struct clk *parent = __clk_get_parent(hw->clk);

	if (parent && (rate==__clk_get_rate(parent))) {
		clk_debug("pll %s round rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		return rate;
	}

	return (pll_com_get_best_set(rate, rk3188_pll_com_table)->rate);
}

static int _pll_clk_set_rate_3188(struct pll_clk_set *clk_set,
		struct clk_hw *hw)
{
	struct clk_pll *pll = to_clk_pll(hw);
	unsigned long flags = 0;


	clk_debug("%s start!\n", __func__);

	if(pll->lock)
		spin_lock_irqsave(pll->lock, flags);

	//enter slowmode
	cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift), pll->mode_offset);
	//pll power down
	cru_writel((0x1 << (16+1)) | (0x1<<1), pll->reg + RK3188_PLL_CON(3));
	dsb();
	dsb();
	dsb();
	dsb();
	dsb();
	dsb();
	cru_writel(clk_set->pllcon0, pll->reg + RK3188_PLL_CON(0));
	cru_writel(clk_set->pllcon1, pll->reg + RK3188_PLL_CON(1));

	udelay(1);

	//pll no power down
	cru_writel((0x1<<(16+1)), pll->reg + RK3188_PLL_CON(3));

	pll_wait_lock(hw);

	//return from slow
	cru_writel(_RK3188_PLL_MODE_NORM_SET(pll->mode_shift), pll->mode_offset);

	if (pll->lock)
		spin_unlock_irqrestore(pll->lock, flags);

	clk_debug("pll %s dump reg: con0=0x%08x, con1=0x%08x, mode=0x%08x\n",
			__clk_get_name(hw->clk),
			cru_readl(pll->reg + RK3188_PLL_CON(0)),
			cru_readl(pll->reg + RK3188_PLL_CON(1)),
			cru_readl(pll->mode_offset));

	clk_debug("%s end!\n", __func__);

	return 0;
}

static int clk_pll_set_rate_3188(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct clk_pll *pll = to_clk_pll(hw);
	struct pll_clk_set *clk_set = (struct pll_clk_set *)(rk3188_pll_com_table);
	int ret = 0;


	if (rate == parent_rate) {
		clk_debug("pll %s set rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift),
				pll->mode_offset);
		/* pll power down */
		cru_writel((0x1 << (16+1)) | (0x1<<1), pll->reg + RK3188_PLL_CON(3));
		clk_debug("pll %s enter slow mode, set rate OK!\n",
				__clk_get_name(hw->clk));
		return 0;
	}

	while(clk_set->rate) {
		if (clk_set->rate == rate) {
			break;
		}
		clk_set++;
	}

	if (clk_set->rate == rate) {
		ret = _pll_clk_set_rate_3188(clk_set, hw);
		clk_debug("pll %s set rate=%lu OK!\n", __clk_get_name(hw->clk),
				rate);
	} else {
		clk_err("pll %s is no corresponding rate=%lu\n",
				__clk_get_name(hw->clk), rate);
		return -EINVAL;
	}

	return ret;
}

static const struct clk_ops clk_pll_ops_3188 = {
	.recalc_rate = clk_pll_recalc_rate_3188,
	.round_rate = clk_pll_round_rate_3188,
	.set_rate = clk_pll_set_rate_3188,
};


/* CLK_PLL_3188_APLL type ops */
static unsigned long clk_pll_recalc_rate_3188_apll(struct clk_hw *hw,
		unsigned long parent_rate)
{
	return clk_pll_recalc_rate_3188(hw, parent_rate);
}

static long clk_pll_round_rate_3188_apll(struct clk_hw *hw, unsigned long rate,
		unsigned long *prate)
{
	struct clk *parent = __clk_get_parent(hw->clk);

	if (parent && (rate==__clk_get_rate(parent))) {
		clk_debug("pll %s round rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		return rate;
	}

	return (apll_get_best_set(rate, rk3188_apll_table)->rate);
}

/* 1: use, 0: no use */
#define RK3188_USE_ARM_GPLL	1

static int clk_pll_set_rate_3188_apll(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct clk_pll *pll = to_clk_pll(hw);
	struct clk *clk = hw->clk;
	struct clk *arm_gpll = __clk_lookup("clk_arm_gpll");
	unsigned long arm_gpll_rate;
	const struct apll_clk_set *ps;
	u32 old_aclk_div = 0, new_aclk_div = 0;
	u32 temp_div;
	unsigned long flags;
	int sel_gpll = 0;


	if (rate == parent_rate) {
		clk_debug("pll %s set rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift),
				pll->mode_offset);
		/* pll power down */
		cru_writel((0x1 << (16+1)) | (0x1<<1), pll->reg + RK3188_PLL_CON(3));
		clk_debug("pll %s enter slow mode, set rate OK!\n",
				__clk_get_name(hw->clk));
		return 0;
	}


#if !RK3188_USE_ARM_GPLL
	goto CHANGE_APLL;
#endif

	/* prepare arm_gpll before reparent clk_core to it */
	if (!arm_gpll) {
		clk_err("clk arm_gpll is NULL!\n");
		goto CHANGE_APLL;
	}

	/* In rk3188, arm_gpll and cpu_gpll share a same gate,
	 * and aclk_cpu selects cpu_gpll as parent, thus this
	 * gate must keep enabled.
	 */
#if 0
	if (clk_prepare(arm_gpll)) {
		clk_err("fail to prepare arm_gpll path\n");
		clk_unprepare(arm_gpll);
		goto CHANGE_APLL;
	}

	if (clk_enable(arm_gpll)) {
		clk_err("fail to enable arm_gpll path\n");
		clk_disable(arm_gpll);
		clk_unprepare(arm_gpll);
		goto CHANGE_APLL;
	}
#endif

	arm_gpll_rate = __clk_get_rate(arm_gpll);
	temp_div = DIV_ROUND_UP(arm_gpll_rate, __clk_get_rate(clk));
	temp_div = (temp_div == 0) ? 1 : temp_div;
	if (temp_div > RK3188_CORE_CLK_MAX_DIV) {
		clk_debug("temp_div %d > max_div %d\n", temp_div,
				RK3188_CORE_CLK_MAX_DIV);
		clk_debug("can't get rate %lu from arm_gpll rate %lu\n",
				__clk_get_rate(clk), arm_gpll_rate);
		//clk_disable(arm_gpll);
		//clk_unprepare(arm_gpll);
		goto CHANGE_APLL;
	}

	local_irq_save(flags);

	/* firstly set div, then select arm_gpll path */
	cru_writel(RK3188_CORE_CLK_DIV_W_MSK|RK3188_CORE_CLK_DIV(temp_div),
			RK3188_CRU_CLKSELS_CON(0));
	cru_writel(RK3188_CORE_SEL_PLL_W_MSK|RK3188_CORE_SEL_GPLL,
			RK3188_CRU_CLKSELS_CON(0));

	sel_gpll = 1;
	//loops_per_jiffy = CLK_LOOPS_RECALC(arm_gpll_rate) / temp_div;
	smp_wmb();

	local_irq_restore(flags);

	clk_debug("temp select arm_gpll path, get rate %lu\n",
			arm_gpll_rate/temp_div);
	clk_debug("from arm_gpll rate %lu, temp_div %d\n", arm_gpll_rate,
			temp_div);

CHANGE_APLL:
	ps = apll_get_best_set(rate, rk3188_apll_table);
	clk_debug("apll will set rate %lu\n", ps->rate);
	clk_debug("table con:%08x,%08x,%08x, sel:%08x,%08x\n",
			ps->pllcon0, ps->pllcon1, ps->pllcon2,
			ps->clksel0, ps->clksel1);

	local_irq_save(flags);

	/* If core src don't select gpll, apll need to enter slow mode
	 * before power down
	 */
	//FIXME
	//if (!sel_gpll)
	cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift), pll->mode_offset);

	/* PLL power down */
	cru_writel((0x1 << (16+1)) | (0x1<<1), pll->reg + RK3188_PLL_CON(3));
	dsb();
	dsb();
	dsb();
	dsb();
	dsb();
	dsb();
	cru_writel(ps->pllcon0, pll->reg + RK3188_PLL_CON(0));
	cru_writel(ps->pllcon1, pll->reg + RK3188_PLL_CON(1));

	udelay(1);

	/* PLL power up and wait for locked */
	cru_writel((0x1<<(16+1)), pll->reg + RK3188_PLL_CON(3));
	pll_wait_lock(hw);

	old_aclk_div = RK3188_GET_CORE_ACLK_VAL(cru_readl(RK3188_CRU_CLKSELS_CON(1)) &
			RK3188_CORE_ACLK_MSK);
	new_aclk_div = RK3188_GET_CORE_ACLK_VAL(ps->clksel1 & RK3188_CORE_ACLK_MSK);

	if (new_aclk_div >= old_aclk_div) {
		cru_writel(ps->clksel0, RK3188_CRU_CLKSELS_CON(0));
		cru_writel(ps->clksel1, RK3188_CRU_CLKSELS_CON(1));
	}

	/* PLL return from slow mode */
	//FIXME
	//if (!sel_gpll)
	cru_writel(_RK3188_PLL_MODE_NORM_SET(pll->mode_shift), pll->mode_offset);

	/* reparent to apll, and set div to 1 */
	if (sel_gpll) {
		cru_writel(RK3188_CORE_SEL_PLL_W_MSK|RK3188_CORE_SEL_APLL,
				RK3188_CRU_CLKSELS_CON(0));
		cru_writel(RK3188_CORE_CLK_DIV_W_MSK|RK3188_CORE_CLK_DIV(1),
				RK3188_CRU_CLKSELS_CON(0));
	}

	if (old_aclk_div > new_aclk_div) {
		cru_writel(ps->clksel0, RK3188_CRU_CLKSELS_CON(0));
		cru_writel(ps->clksel1, RK3188_CRU_CLKSELS_CON(1));
	}

	//loops_per_jiffy = ps->lpj;
	smp_wmb();

	local_irq_restore(flags);

	if (sel_gpll) {
		sel_gpll = 0;
		//clk_disable(arm_gpll);
		//clk_unprepare(arm_gpll);
	}

	//clk_debug("apll set loops_per_jiffy =%lu\n", loops_per_jiffy);

	clk_debug("apll set rate %lu, con(%x,%x,%x,%x), sel(%x,%x)\n",
			ps->rate,
			cru_readl(pll->reg + RK3188_PLL_CON(0)),
			cru_readl(pll->reg + RK3188_PLL_CON(1)),
			cru_readl(pll->reg + RK3188_PLL_CON(2)),
			cru_readl(pll->reg + RK3188_PLL_CON(3)),
			cru_readl(RK3188_CRU_CLKSELS_CON(0)),
			cru_readl(RK3188_CRU_CLKSELS_CON(1)));

	return 0;
}

static const struct clk_ops clk_pll_ops_3188_apll = {
	.recalc_rate = clk_pll_recalc_rate_3188_apll,
	.round_rate = clk_pll_round_rate_3188_apll,
	.set_rate = clk_pll_set_rate_3188_apll,
};


/* CLK_PLL_3188PLUS type ops */
static unsigned long clk_pll_recalc_rate_3188plus(struct clk_hw *hw,
		unsigned long parent_rate)
{
	struct clk_pll *pll = to_clk_pll(hw);
	unsigned long rate;


	if (_RK3188_PLL_MODE_IS_NORM(pll->mode_offset, pll->mode_shift)) {
		u32 pll_con0 = cru_readl(pll->reg + RK3188_PLL_CON(0));
		u32 pll_con1 = cru_readl(pll->reg + RK3188_PLL_CON(1));

		u64 rate64 = (u64)parent_rate * RK3188PLUS_PLL_NF(pll_con1);

		do_div(rate64, RK3188PLUS_PLL_NR(pll_con0));
		do_div(rate64, RK3188PLUS_PLL_NO(pll_con0));

		rate = rate64;
	} else {
		/*FIXME*/
		rate = parent_rate;
		clk_debug("pll %s is in slow mode\n", __clk_get_name(hw->clk));
	}

	clk_debug("pll %s recalc rate =%lu\n", __clk_get_name(hw->clk), rate);

	return rate;
}

static long clk_pll_round_rate_3188plus(struct clk_hw *hw, unsigned long rate,
		unsigned long *prate)
{
	struct clk *parent = __clk_get_parent(hw->clk);

	if (parent && (rate==__clk_get_rate(parent))) {
		clk_debug("pll %s round rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		return rate;
	}

	return (pll_com_get_best_set(rate, rk3188plus_pll_com_table)->rate);
}

static int _pll_clk_set_rate_3188plus(struct pll_clk_set *clk_set,
		struct clk_hw *hw)
{
	struct clk_pll *pll = to_clk_pll(hw);
	unsigned long flags = 0;


	clk_debug("%s start!\n", __func__);

	if(pll->lock)
		spin_lock_irqsave(pll->lock, flags);

	//enter slowmode
	cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift), pll->mode_offset);

	//enter rest
	cru_writel(_RK3188PLUS_PLL_RESET_SET(1), pll->reg + RK3188_PLL_CON(3));
//box
	if(!strcmp(__clk_get_name(hw->clk), "clk_cpll")) {
//		cru_writel(0xffff000f, pll->reg + RK3188_PLL_CON(0));
		cru_writel(0xffff0007, pll->reg + RK3188_PLL_CON(0));
		cru_writel(0xffff00c5, pll->reg + RK3188_PLL_CON(1));
	}
	else {
	cru_writel(clk_set->pllcon0, pll->reg + RK3188_PLL_CON(0));
	cru_writel(clk_set->pllcon1, pll->reg + RK3188_PLL_CON(1));
	}
	cru_writel(clk_set->pllcon2, pll->reg + RK3188_PLL_CON(2));

	udelay(5);

	//return from rest
	cru_writel(_RK3188PLUS_PLL_RESET_SET(0), pll->reg + RK3188_PLL_CON(3));

	//wating lock state
	udelay(clk_set->rst_dly);

	pll_wait_lock(hw);

	//return from slow
	cru_writel(_RK3188_PLL_MODE_NORM_SET(pll->mode_shift), pll->mode_offset);
//box
	if (pll->lock) {
		if(!strcmp(__clk_get_name(hw->clk), "clk_cpll")) {
			cru_writel(0, pll->reg + RK3188_PLL_CON(2));
		}
		spin_unlock_irqrestore(pll->lock, flags);
	}
	clk_debug("pll %s dump reg: con0=0x%08x, con1=0x%08x, mode=0x%08x\n",
			__clk_get_name(hw->clk),
			cru_readl(pll->reg + RK3188_PLL_CON(0)),
			cru_readl(pll->reg + RK3188_PLL_CON(1)),
			cru_readl(pll->mode_offset));

	clk_debug("%s end!\n", __func__);

	return 0;
}

static int clk_pll_set_rate_3188plus(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	//struct clk_pll *pll = to_clk_pll(hw);
	struct pll_clk_set *clk_set = (struct pll_clk_set *)(rk3188plus_pll_com_table);
	int ret = 0;

#if 0
	if (rate == parent_rate) {
		clk_debug("pll %s set rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift),
				pll->mode_offset);
		/* pll power down */
		cru_writel((0x1 << (16+1)) | (0x1<<1), pll->reg + RK3188_PLL_CON(3));
		clk_debug("pll %s enter slow mode, set rate OK!\n",
				__clk_get_name(hw->clk));
		return 0;
	}
#endif

	while(clk_set->rate) {
		if (clk_set->rate == rate) {
			break;
		}
		clk_set++;
	}

	if (cpu_is_rk3288() && (rate == 297*MHZ)) {
		if((strncmp(__clk_get_name(hw->clk), "clk_gpll",
			strlen("clk_gpll")) == 0)) {

			printk("rk3288 set GPLL BW 20 for HDMI!\n");
			clk_set->pllcon2 = RK3188_PLL_CLK_BWADJ_SET(20);
		}
	}

	if (clk_set->rate == rate) {
		ret = _pll_clk_set_rate_3188plus(clk_set, hw);
		clk_debug("pll %s set rate=%lu OK!\n", __clk_get_name(hw->clk),
				rate);
	} else {
		clk_err("pll %s is no corresponding rate=%lu\n",
				__clk_get_name(hw->clk), rate);
		return -EINVAL;
	}

	return ret;
}

static const struct clk_ops clk_pll_ops_3188plus = {
	.recalc_rate = clk_pll_recalc_rate_3188plus,
	.round_rate = clk_pll_round_rate_3188plus,
	.set_rate = clk_pll_set_rate_3188plus,
};

/* CLK_PLL_3188PLUS_AUTO type ops */
#define PLL_FREF_MIN (269*KHZ)
#define PLL_FREF_MAX (2200*MHZ)

#define PLL_FVCO_MIN (440*MHZ)
#define PLL_FVCO_MAX (2200*MHZ)

#define PLL_FOUT_MIN (27500*KHZ) 
#define PLL_FOUT_MAX (2200*MHZ)

#define PLL_NF_MAX (4096)
#define PLL_NR_MAX (64)
#define PLL_NO_MAX (16)

static u32 clk_gcd(u32 numerator, u32 denominator)
{
        u32 a, b;

        if (!numerator || !denominator)
                return 0;
        if (numerator > denominator) {
                a = numerator;
                b = denominator;
        } else {
                a = denominator;
                b = numerator;
        }
        while (b != 0) {
                int r = b;
                b = a % b;
                a = r;
        }

        return a;
}

/* FIXME: calc using u64 */
static int pll_clk_get_best_set(unsigned long fin_hz, unsigned long fout_hz,
				u32 *best_nr, u32 *best_nf, u32 *best_no)
{
        u32 nr, nf, no, nonr;
        u32 nr_out, nf_out, no_out;
        u32 n;
        u32 YFfenzi;
        u32 YFfenmu;
        u64 fref, fvco, fout;
        u32 gcd_val = 0;


        nr_out = PLL_NR_MAX + 1;
        no_out = 0;

//	printk("pll_clk_get_set fin=%lu,fout=%lu\n", fin_hz, fout_hz);
        if(!fin_hz || !fout_hz || fout_hz == fin_hz)
                return -EINVAL;
        gcd_val = clk_gcd(fin_hz, fout_hz);

//      printk("gcd_val = %d\n",gcd_val);

        YFfenzi = fout_hz / gcd_val;
        YFfenmu = fin_hz / gcd_val;

//      printk("YFfenzi = %d, YFfenmu = %d\n",YFfenzi,YFfenmu);

	for(n = 1;; n++) {
	       nf = YFfenzi * n;
	       nonr = YFfenmu * n;
	       if(nf > PLL_NF_MAX || nonr > (PLL_NO_MAX * PLL_NR_MAX))
		       break;
	       for(no = 1; no <= PLL_NO_MAX; no++) {
		       if(!(no == 1 || !(no % 2)))
			       continue;

		       if(nonr % no)
			       continue;
		       nr = nonr / no;

		       if(nr > PLL_NR_MAX) //PLL_NR_MAX
			       continue;

		       fref = fin_hz / nr;
		       if(fref < PLL_FREF_MIN || fref > PLL_FREF_MAX)
			       continue;

		       fvco = fref * nf;
		       if(fvco < PLL_FVCO_MIN || fvco > PLL_FVCO_MAX)
			       continue;
		       fout = fvco / no;
		       if(fout < PLL_FOUT_MIN || fout > PLL_FOUT_MAX)
			       continue;

		       /* output all available PLL settings */
		       //printk("nr=%d,\tnf=%d,\tno=%d\n",nr,nf,no);
		       //printk("_PLL_SET_CLKS(%lu,\t%d,\t%d,\t%d),\n",fout_hz/KHZ,nr,nf,no);

		       /* select the best from all available PLL settings */
		       if((nr < nr_out) || ((nr == nr_out)&&(no > no_out)))
		       {
			       nr_out = nr;
			       nf_out = nf;
			       no_out = no;
		       }
	       }

       }

        /* output the best PLL setting */
        if((nr_out <= PLL_NR_MAX) && (no_out > 0)){
                //printk("_PLL_SET_CLKS(%lu,\t%d,\t%d,\t%d),\n",fout_hz/KHZ,nr_out,nf_out,no_out);
		if(best_nr && best_nf && best_no){
			*best_nr = nr_out;
			*best_nf = nf_out;
			*best_no = no_out;
		}
		return 0;
	} else {
		return -EINVAL;
	}
}

static unsigned long clk_pll_recalc_rate_3188plus_auto(struct clk_hw *hw,
		unsigned long parent_rate)
{
	return clk_pll_recalc_rate_3188plus(hw, parent_rate);
}

static long clk_pll_round_rate_3188plus_auto(struct clk_hw *hw, unsigned long rate,
		unsigned long *prate)
{
	unsigned long best;

	for(best=rate; best>0; best--){
		if(!pll_clk_get_best_set(*prate, best, NULL, NULL, NULL))
			return best;
	}

	return 0;
}

static int clk_pll_set_rate_3188plus_auto(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	unsigned long best;
	u32 nr,nf,no;
	struct pll_clk_set clk_set;
	int ret;


	best = clk_pll_round_rate_3188plus_auto(hw, rate, &parent_rate);

	if(!best)
		return -EINVAL;

	pll_clk_get_best_set(parent_rate, best, &nr, &nf, &no);

	/* prepare clk_set */
	clk_set.rate = best;
	clk_set.pllcon0 = RK3188PLUS_PLL_CLKR_SET(nr)|RK3188PLUS_PLL_CLKOD_SET(no);
	clk_set.pllcon1 = RK3188PLUS_PLL_CLKF_SET(nf);
	clk_set.pllcon2 = RK3188PLUS_PLL_CLK_BWADJ_SET(nf >> 1);
	clk_set.rst_dly = ((nr*500)/24+1);

	ret = _pll_clk_set_rate_3188plus(&clk_set, hw);
	clk_debug("pll %s set rate=%lu OK!\n", __clk_get_name(hw->clk), best);

	return ret;
}


static const struct clk_ops clk_pll_ops_3188plus_auto = {
	.recalc_rate = clk_pll_recalc_rate_3188plus_auto,
	.round_rate = clk_pll_round_rate_3188plus_auto,
	.set_rate = clk_pll_set_rate_3188plus_auto,
};


/* CLK_PLL_3188PLUS_APLL type ops */
static unsigned long clk_pll_recalc_rate_3188plus_apll(struct clk_hw *hw,
		unsigned long parent_rate)
{
	return clk_pll_recalc_rate_3188plus(hw, parent_rate);
}

static long clk_pll_round_rate_3188plus_apll(struct clk_hw *hw, unsigned long rate,
		unsigned long *prate)
{
	return clk_pll_round_rate_3188_apll(hw, rate, prate);
}

/* 1: use, 0: no use */
#define RK3188PLUS_USE_ARM_GPLL	1

static int clk_pll_set_rate_3188plus_apll(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct clk_pll *pll = to_clk_pll(hw);
	struct clk *clk = hw->clk;
	struct clk *arm_gpll = __clk_lookup("clk_arm_gpll");
	unsigned long arm_gpll_rate;
	const struct apll_clk_set *ps;
	u32 old_aclk_div = 0, new_aclk_div = 0;
	u32 temp_div;
	unsigned long flags;
	int sel_gpll = 0;

#if 0
	if (rate == parent_rate) {
		clk_debug("pll %s set rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift),
				pll->mode_offset);
		/* pll power down */
		cru_writel((0x1 << (16+1)) | (0x1<<1), pll->reg + RK3188_PLL_CON(3));
		clk_debug("pll %s enter slow mode, set rate OK!\n",
				__clk_get_name(hw->clk));
		return 0;
	}
#endif


#if !RK3188PLUS_USE_ARM_GPLL
	goto CHANGE_APLL;
#endif

	/* prepare arm_gpll before reparent clk_core to it */
	if (!arm_gpll) {
		clk_err("clk arm_gpll is NULL!\n");
		goto CHANGE_APLL;
	}

	/* In rk3188plus, arm_gpll and cpu_gpll share a same gate,
	 * and aclk_cpu selects cpu_gpll as parent, thus this
	 * gate must keep enabled.
	 */
#if 0
	if (clk_prepare(arm_gpll)) {
		clk_err("fail to prepare arm_gpll path\n");
		clk_unprepare(arm_gpll);
		goto CHANGE_APLL;
	}

	if (clk_enable(arm_gpll)) {
		clk_err("fail to enable arm_gpll path\n");
		clk_disable(arm_gpll);
		clk_unprepare(arm_gpll);
		goto CHANGE_APLL;
	}
#endif

	arm_gpll_rate = __clk_get_rate(arm_gpll);
	temp_div = DIV_ROUND_UP(arm_gpll_rate, __clk_get_rate(clk));
	temp_div = (temp_div == 0) ? 1 : temp_div;
	if (temp_div > RK3188_CORE_CLK_MAX_DIV) {
		clk_debug("temp_div %d > max_div %d\n", temp_div,
				RK3188_CORE_CLK_MAX_DIV);
		clk_debug("can't get rate %lu from arm_gpll rate %lu\n",
				__clk_get_rate(clk), arm_gpll_rate);
		//clk_disable(arm_gpll);
		//clk_unprepare(arm_gpll);
		goto CHANGE_APLL;
	}

	local_irq_save(flags);

	/* firstly set div, then select arm_gpll path */
	cru_writel(RK3188_CORE_CLK_DIV_W_MSK|RK3188_CORE_CLK_DIV(temp_div),
			RK3188_CRU_CLKSELS_CON(0));
	cru_writel(RK3188_CORE_SEL_PLL_W_MSK|RK3188_CORE_SEL_GPLL,
			RK3188_CRU_CLKSELS_CON(0));

	sel_gpll = 1;
	//loops_per_jiffy = CLK_LOOPS_RECALC(arm_gpll_rate) / temp_div;
	smp_wmb();

	local_irq_restore(flags);

	clk_debug("temp select arm_gpll path, get rate %lu\n",
			arm_gpll_rate/temp_div);
	clk_debug("from arm_gpll rate %lu, temp_div %d\n", arm_gpll_rate,
			temp_div);

CHANGE_APLL:
	ps = apll_get_best_set(rate, rk3188_apll_table);
	clk_debug("apll will set rate %lu\n", ps->rate);
	clk_debug("table con:%08x,%08x,%08x, sel:%08x,%08x\n",
			ps->pllcon0, ps->pllcon1, ps->pllcon2,
			ps->clksel0, ps->clksel1);

	local_irq_save(flags);

	/* If core src don't select gpll, apll need to enter slow mode
	 * before reset
	 */
	//FIXME
	//if (!sel_gpll)
	cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift), pll->mode_offset);

	/* PLL enter rest */
	cru_writel(_RK3188PLUS_PLL_RESET_SET(1), pll->reg + RK3188_PLL_CON(3));

	cru_writel(ps->pllcon0, pll->reg + RK3188_PLL_CON(0));
	cru_writel(ps->pllcon1, pll->reg + RK3188_PLL_CON(1));
	cru_writel(ps->pllcon2, pll->reg + RK3188_PLL_CON(2));

	udelay(5);

	/* return from rest */
	cru_writel(_RK3188PLUS_PLL_RESET_SET(0), pll->reg + RK3188_PLL_CON(3));

	//wating lock state
	udelay(ps->rst_dly);
	pll_wait_lock(hw);

	old_aclk_div = RK3188_GET_CORE_ACLK_VAL(cru_readl(RK3188_CRU_CLKSELS_CON(1)) &
			RK3188_CORE_ACLK_MSK);
	new_aclk_div = RK3188_GET_CORE_ACLK_VAL(ps->clksel1 & RK3188_CORE_ACLK_MSK);

	if (new_aclk_div >= old_aclk_div) {
		cru_writel(ps->clksel0, RK3188_CRU_CLKSELS_CON(0));
		cru_writel(ps->clksel1, RK3188_CRU_CLKSELS_CON(1));
	}

	/* PLL return from slow mode */
	//FIXME
	//if (!sel_gpll)
	cru_writel(_RK3188_PLL_MODE_NORM_SET(pll->mode_shift), pll->mode_offset);

	/* reparent to apll, and set div to 1 */
	if (sel_gpll) {
		cru_writel(RK3188_CORE_SEL_PLL_W_MSK|RK3188_CORE_SEL_APLL,
				RK3188_CRU_CLKSELS_CON(0));
		cru_writel(RK3188_CORE_CLK_DIV_W_MSK|RK3188_CORE_CLK_DIV(1),
				RK3188_CRU_CLKSELS_CON(0));
	}

	if (old_aclk_div > new_aclk_div) {
		cru_writel(ps->clksel0, RK3188_CRU_CLKSELS_CON(0));
		cru_writel(ps->clksel1, RK3188_CRU_CLKSELS_CON(1));
	}

	//loops_per_jiffy = ps->lpj;
	smp_wmb();

	local_irq_restore(flags);

	if (sel_gpll) {
		sel_gpll = 0;
		//clk_disable(arm_gpll);
		//clk_unprepare(arm_gpll);
	}

	//clk_debug("apll set loops_per_jiffy =%lu\n", loops_per_jiffy);

	clk_debug("apll set rate %lu, con(%x,%x,%x,%x), sel(%x,%x)\n",
			ps->rate,
			cru_readl(pll->reg + RK3188_PLL_CON(0)),
			cru_readl(pll->reg + RK3188_PLL_CON(1)),
			cru_readl(pll->reg + RK3188_PLL_CON(2)),
			cru_readl(pll->reg + RK3188_PLL_CON(3)),
			cru_readl(RK3188_CRU_CLKSELS_CON(0)),
			cru_readl(RK3188_CRU_CLKSELS_CON(1)));

	return 0;
}

static const struct clk_ops clk_pll_ops_3188plus_apll = {
	.recalc_rate = clk_pll_recalc_rate_3188plus_apll,
	.round_rate = clk_pll_round_rate_3188plus_apll,
	.set_rate = clk_pll_set_rate_3188plus_apll,
};

/* CLK_PLL_3288_APLL type ops */
static unsigned long clk_pll_recalc_rate_3288_apll(struct clk_hw *hw,
		unsigned long parent_rate)
{
	return clk_pll_recalc_rate_3188plus(hw, parent_rate);
}

static long clk_pll_round_rate_3288_apll(struct clk_hw *hw, unsigned long rate,
		unsigned long *prate)
{
	struct clk *parent = __clk_get_parent(hw->clk);

	if (parent && (rate==__clk_get_rate(parent))) {
		clk_debug("pll %s round rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		return rate;
	}

	return (apll_get_best_set(rate, rk3288_apll_table)->rate);
}

/* 1: use, 0: no use */
#define RK3288_USE_ARM_GPLL	1

static int clk_pll_set_rate_3288_apll(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct clk_pll *pll = to_clk_pll(hw);
	struct clk *clk = hw->clk;
	struct clk *arm_gpll = __clk_lookup("clk_arm_gpll");
	unsigned long arm_gpll_rate, temp_rate, old_rate;
	const struct apll_clk_set *ps;
//	u32 old_aclk_div = 0, new_aclk_div = 0;
	u32 temp_div;
	unsigned long flags;
	int sel_gpll = 0;


#if 0
	if (rate == parent_rate) {
		clk_debug("pll %s set rate=%lu equal to parent rate\n",
				__clk_get_name(hw->clk), rate);
		cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift),
				pll->mode_offset);
		/* pll power down */
		cru_writel((0x1 << (16+1)) | (0x1<<1), pll->reg + RK3188_PLL_CON(3));
		clk_debug("pll %s enter slow mode, set rate OK!\n",
				__clk_get_name(hw->clk));
		return 0;
	}
#endif

#if !RK3288_USE_ARM_GPLL
	goto CHANGE_APLL;
#endif

	/* prepare arm_gpll before reparent clk_core to it */
	if (!arm_gpll) {
		clk_err("clk arm_gpll is NULL!\n");
		goto CHANGE_APLL;
	}

	arm_gpll_rate = __clk_get_rate(arm_gpll);
	old_rate = __clk_get_rate(clk);

	temp_rate = (old_rate > rate) ? old_rate : rate;
	temp_div = DIV_ROUND_UP(arm_gpll_rate, temp_rate);

	if (temp_div > RK3288_CORE_CLK_MAX_DIV) {
		clk_debug("temp_div %d > max_div %d\n", temp_div,
				RK3288_CORE_CLK_MAX_DIV);
		clk_debug("can't get rate %lu from arm_gpll rate %lu\n",
				__clk_get_rate(clk), arm_gpll_rate);
		goto CHANGE_APLL;
	}

#if 0
	if (clk_prepare(arm_gpll)) {
		clk_err("fail to prepare arm_gpll path\n");
		clk_unprepare(arm_gpll);
		goto CHANGE_APLL;
	}

	if (clk_enable(arm_gpll)) {
		clk_err("fail to enable arm_gpll path\n");
		clk_disable(arm_gpll);
		clk_unprepare(arm_gpll);
		goto CHANGE_APLL;
	}
#endif

	local_irq_save(flags);

	/* select gpll */
	if (temp_div == 1) {
		/* when old_rate/2 < (old_rate-arm_gpll_rate),
		   we can set div to make rate change more gently */
		if (old_rate > (2*arm_gpll_rate)) {
			cru_writel(RK3288_CORE_CLK_DIV(2), RK3288_CRU_CLKSELS_CON(0));
			udelay(10);
			cru_writel(RK3288_CORE_CLK_DIV(3), RK3288_CRU_CLKSELS_CON(0));
			udelay(10);
			cru_writel(RK3288_CORE_SEL_PLL_W_MSK|RK3288_CORE_SEL_GPLL,
				RK3288_CRU_CLKSELS_CON(0));
			udelay(10);
			cru_writel(RK3288_CORE_CLK_DIV(2), RK3288_CRU_CLKSELS_CON(0));
			udelay(10);
			cru_writel(RK3288_CORE_CLK_DIV(1), RK3288_CRU_CLKSELS_CON(0));
		} else {
			cru_writel(RK3288_CORE_SEL_PLL_W_MSK|RK3288_CORE_SEL_GPLL,
				RK3288_CRU_CLKSELS_CON(0));
		}
	} else {
		cru_writel(RK3288_CORE_CLK_DIV(temp_div), RK3288_CRU_CLKSELS_CON(0));
		cru_writel(RK3288_CORE_SEL_PLL_W_MSK|RK3288_CORE_SEL_GPLL,
				RK3288_CRU_CLKSELS_CON(0));
	}

	sel_gpll = 1;
	//loops_per_jiffy = CLK_LOOPS_RECALC(arm_gpll_rate) / temp_div;
	smp_wmb();

	local_irq_restore(flags);

	clk_debug("temp select arm_gpll path, get rate %lu\n",
			arm_gpll_rate/temp_div);
	clk_debug("from arm_gpll rate %lu, temp_div %d\n", arm_gpll_rate,
			temp_div);

CHANGE_APLL:
	if (rate > SAFETY_FREQ)
		ps = apll_get_best_set(SAFETY_FREQ, rk3288_apll_table);
	else
		ps = apll_get_best_set(rate, rk3288_apll_table);
	clk_debug("apll will set rate %lu\n", ps->rate);
	clk_debug("table con:%08x,%08x,%08x, sel:%08x,%08x\n",
			ps->pllcon0, ps->pllcon1, ps->pllcon2,
			ps->clksel0, ps->clksel1);

	local_irq_save(flags);

	/* If core src don't select gpll, apll need to enter slow mode
	 * before reset
	 */
	//FIXME
	//if (!sel_gpll)
	cru_writel(_RK3188_PLL_MODE_SLOW_SET(pll->mode_shift), pll->mode_offset);

	/* PLL enter rest */
	cru_writel(_RK3188PLUS_PLL_RESET_SET(1), pll->reg + RK3188_PLL_CON(3));

	cru_writel(ps->pllcon0, pll->reg + RK3188_PLL_CON(0));
	cru_writel(ps->pllcon1, pll->reg + RK3188_PLL_CON(1));
	cru_writel(ps->pllcon2, pll->reg + RK3188_PLL_CON(2));

	udelay(5);

	/* return from rest */
	cru_writel(_RK3188PLUS_PLL_RESET_SET(0), pll->reg + RK3188_PLL_CON(3));

	//wating lock state
	udelay(ps->rst_dly);
	pll_wait_lock(hw);

	if (rate >= __clk_get_rate(hw->clk)) {
		cru_writel(ps->clksel0, RK3288_CRU_CLKSELS_CON(0));
		cru_writel(ps->clksel1, RK3288_CRU_CLKSELS_CON(37));
	}

	/* PLL return from slow mode */
	//FIXME
	//if (!sel_gpll)
	cru_writel(_RK3188_PLL_MODE_NORM_SET(pll->mode_shift), pll->mode_offset);

	/* reparent to apll, and set div to 1 */
	if (sel_gpll) {
		if (temp_div == 1) {
			/* when rate/2 < (old_rate-arm_gpll_rate),
		           we can set div to make rate change more gently */
			if (rate > (2*arm_gpll_rate)) {
				cru_writel(RK3288_CORE_CLK_DIV(2), RK3288_CRU_CLKSELS_CON(0));
				udelay(10);
				cru_writel(RK3288_CORE_CLK_DIV(3), RK3288_CRU_CLKSELS_CON(0));
				udelay(10);
				cru_writel(RK3288_CORE_SEL_PLL_W_MSK|RK3288_CORE_SEL_APLL,
					RK3288_CRU_CLKSELS_CON(0));
				udelay(10);
				cru_writel(RK3288_CORE_CLK_DIV(2), RK3288_CRU_CLKSELS_CON(0));
				udelay(10);
				cru_writel(RK3288_CORE_CLK_DIV(1), RK3288_CRU_CLKSELS_CON(0));
			} else {
				cru_writel(RK3288_CORE_SEL_PLL_W_MSK|RK3288_CORE_SEL_APLL,
						RK3288_CRU_CLKSELS_CON(0));
			}
		} else {
			cru_writel(RK3288_CORE_SEL_PLL_W_MSK|RK3288_CORE_SEL_APLL,
				RK3288_CRU_CLKSELS_CON(0));
			cru_writel(RK3288_CORE_CLK_DIV(1), RK3288_CRU_CLKSELS_CON(0));
		}
	}

	if (rate < __clk_get_rate(hw->clk)) {
		cru_writel(ps->clksel0, RK3288_CRU_CLKSELS_CON(0));
		cru_writel(ps->clksel1, RK3288_CRU_CLKSELS_CON(37));
	}

	//loops_per_jiffy = ps->lpj;
	smp_wmb();

	local_irq_restore(flags);

	if (sel_gpll) {
		sel_gpll = 0;
		//clk_disable(arm_gpll);
		//clk_unprepare(arm_gpll);
	}

	//clk_debug("apll set loops_per_jiffy =%lu\n", loops_per_jiffy);

	clk_debug("apll set rate %lu, con(%x,%x,%x,%x), sel(%x,%x)\n",
			ps->rate,
			cru_readl(pll->reg + RK3188_PLL_CON(0)),
			cru_readl(pll->reg + RK3188_PLL_CON(1)),
			cru_readl(pll->reg + RK3188_PLL_CON(2)),
			cru_readl(pll->reg + RK3188_PLL_CON(3)),
			cru_readl(RK3288_CRU_CLKSELS_CON(0)),
			cru_readl(RK3288_CRU_CLKSELS_CON(1)));

	return 0;
}


static const struct clk_ops clk_pll_ops_3288_apll = {
	.recalc_rate = clk_pll_recalc_rate_3288_apll,
	.round_rate = clk_pll_round_rate_3288_apll,
	.set_rate = clk_pll_set_rate_3288_apll,
};



const struct clk_ops *rk_get_pll_ops(u32 pll_flags)
{
	switch (pll_flags) {
		case CLK_PLL_3188:
			return &clk_pll_ops_3188;

		case CLK_PLL_3188_APLL:
			return &clk_pll_ops_3188_apll;

		case CLK_PLL_3188PLUS:
			return &clk_pll_ops_3188plus;

		case CLK_PLL_3188PLUS_APLL:
			return &clk_pll_ops_3188plus_apll;

		case CLK_PLL_3288_APLL:
			return &clk_pll_ops_3288_apll;

		case CLK_PLL_3188PLUS_AUTO:
			return &clk_pll_ops_3188plus_auto;

		default:
			clk_err("%s: unknown pll_flags!\n", __func__);
			return NULL;
	}
}

struct clk *rk_clk_register_pll(struct device *dev, const char *name,
		const char *parent_name, unsigned long flags, u32 reg,
		u32 width, u32 mode_offset, u8 mode_shift,
		u32 status_offset, u8 status_shift, u32 pll_flags,
		spinlock_t *lock)
{
	struct clk_pll *pll;
	struct clk *clk;
	struct clk_init_data init;


	clk_debug("%s: pll name = %s, pll_flags = 0x%x, register start!\n",
			__func__, name, pll_flags);

	/* allocate the pll */
	pll = kzalloc(sizeof(struct clk_pll), GFP_KERNEL);
	if (!pll) {
		clk_err("%s: could not allocate pll clk\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	init.name = name;
	init.flags = flags;
	init.parent_names = (parent_name ? &parent_name: NULL);
	init.num_parents = (parent_name ? 1 : 0);
	init.ops = rk_get_pll_ops(pll_flags);

	/* struct clk_pll assignments */
	pll->reg = reg;
	pll->width = width;
	pll->mode_offset = mode_offset;
	pll->mode_shift = mode_shift;
	pll->status_offset = status_offset;
	pll->status_shift = status_shift;
	pll->flags = pll_flags;
	pll->lock = lock;
	pll->hw.init = &init;

	/* register the clock */
	clk = clk_register(dev, &pll->hw);

	if (IS_ERR(clk))
		kfree(pll);

	clk_debug("%s: pll name = %s, pll_flags = 0x%x, register finish!\n",
			__func__, name, pll_flags);

	return clk;
}

