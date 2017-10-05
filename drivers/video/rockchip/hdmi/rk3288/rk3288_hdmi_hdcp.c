#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/miscdevice.h>
#include <linux/workqueue.h>
#include <linux/firmware.h>
#include <linux/delay.h>
#include "rk3288_hdmi.h"
#include "rk3288_hdmi_hw.h"

#define	HDCP_KEY_SIZE		308
#define HDCP_PRIVATE_KEY_SIZE	280
#define HDCP_KEY_SHA_SIZE	20
#define HDCP_KEY_SEED_SIZE	2
#define KSV_LEN			5
#define HEADER			10
#define SHAMAX			20

#define MAX_DOWNSTREAM_DEVICE_NUM	5

struct hdcp_keys {
	u8 KSV[8];
	u8 DeviceKey[HDCP_PRIVATE_KEY_SIZE];
	u8 sha1[HDCP_KEY_SHA_SIZE];
};

struct hdcp {
	struct hdmi		*hdmi;
	int			enable;
	int			retry_times;
	struct hdcp_keys	*keys;
	char			*seeds;
	int			invalidkey;
	char			*invalidkeys;
};

typedef struct
{
	u8 mLength[8];
	u8 mBlock[64];
	int mIndex;
	int mComputed;
	int mCorrupted;
	unsigned int mDigest[5];
} sha_t;

static struct miscdevice mdev;
struct hdcp *hdcp = NULL;

static void sha_reset(sha_t *sha)
{
	u32 i = 0;

	sha->mIndex = 0;
	sha->mComputed = false;
	sha->mCorrupted = false;
	for (i = 0; i < sizeof(sha->mLength); i++)
		sha->mLength[i] = 0;

	sha->mDigest[0] = 0x67452301;
	sha->mDigest[1] = 0xEFCDAB89;
	sha->mDigest[2] = 0x98BADCFE;
	sha->mDigest[3] = 0x10325476;
	sha->mDigest[4] = 0xC3D2E1F0;
}
#define shacircularshift(bits,word) ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))
void sha_processblock(sha_t *sha)
{
	const unsigned K[] = {
	/* constants defined in SHA-1 */
	0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
	unsigned W[80]; /* word sequence */
	unsigned A, B, C, D, E; /* word buffers */
	unsigned temp = 0;
	int t = 0;

	/* Initialize the first 16 words in the array W */
	for (t = 0; t < 80; t++) {
		if (t < 16) {
			W[t] = ((unsigned) sha->mBlock[t * 4 + 0]) << 24;
			W[t] |= ((unsigned) sha->mBlock[t * 4 + 1]) << 16;
			W[t] |= ((unsigned) sha->mBlock[t * 4 + 2]) << 8;
			W[t] |= ((unsigned) sha->mBlock[t * 4 + 3]) << 0;
		} else {
			W[t] = shacircularshift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
		}
	}

	A = sha->mDigest[0];
	B = sha->mDigest[1];
	C = sha->mDigest[2];
	D = sha->mDigest[3];
	E = sha->mDigest[4];

	for (t = 0; t < 80; t++) {
		temp = shacircularshift(5, A);
		if (t < 20)
			temp += ((B & C) | ((~B) & D)) + E + W[t] + K[0];
		else if (t < 40)
			temp += (B ^ C ^ D) + E + W[t] + K[1];
		else if (t < 60)
			temp += ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		else
			temp += (B ^ C ^ D) + E + W[t] + K[3];

		E = D;
		D = C;
		C = shacircularshift(30,B);
		B = A;
		A = (temp & 0xFFFFFFFF);
	}

	sha->mDigest[0] = (sha->mDigest[0] + A) & 0xFFFFFFFF;
	sha->mDigest[1] = (sha->mDigest[1] + B) & 0xFFFFFFFF;
	sha->mDigest[2] = (sha->mDigest[2] + C) & 0xFFFFFFFF;
	sha->mDigest[3] = (sha->mDigest[3] + D) & 0xFFFFFFFF;
	sha->mDigest[4] = (sha->mDigest[4] + E) & 0xFFFFFFFF;

	sha->mIndex = 0;
}

static void sha_padmessage(sha_t *sha)
{
	/*
	 *  Check to see if the current message block is too small to hold
	 *  the initial padding bits and length.  If so, we will pad the
	 *  block, process it, and then continue padding into a second
	 *  block.
	 */
	if (sha->mIndex > 55) {
		sha->mBlock[sha->mIndex++] = 0x80;
		while (sha->mIndex < 64)
			sha->mBlock[sha->mIndex++] = 0;

		sha_processblock(sha);
		while (sha->mIndex < 56)
			sha->mBlock[sha->mIndex++] = 0;
	} else {
		sha->mBlock[sha->mIndex++] = 0x80;
		while (sha->mIndex < 56)
			sha->mBlock[sha->mIndex++] = 0;
	}

	/* Store the message length as the last 8 octets */
	sha->mBlock[56] = sha->mLength[7];
	sha->mBlock[57] = sha->mLength[6];
	sha->mBlock[58] = sha->mLength[5];
	sha->mBlock[59] = sha->mLength[4];
	sha->mBlock[60] = sha->mLength[3];
	sha->mBlock[61] = sha->mLength[2];
	sha->mBlock[62] = sha->mLength[1];
	sha->mBlock[63] = sha->mLength[0];

	sha_processblock(sha);
}

static int sha_result(sha_t *sha)
{
	if (sha->mCorrupted == true)
		return false;

	if (sha->mComputed == 0) {
		sha_padmessage(sha);
		sha->mComputed = true;
	}
	return true;
}

static void sha_input(sha_t *sha, const u8 * data, u32 size)
{
	int i = 0;
	unsigned j = 0;
	int rc = true;

	if (data == 0 || size == 0) {
		pr_err("invalid input data");
		return;
	}
	if (sha->mComputed == true || sha->mCorrupted == true) {
		sha->mCorrupted = true;
		return;
	}
	while (size-- && sha->mCorrupted == false) {
		sha->mBlock[sha->mIndex++] = *data;

		for (i = 0; i < 8; i++) {
			rc = true;
			for (j = 0; j < sizeof(sha->mLength); j++) {
				sha->mLength[j]++;
				if (sha->mLength[j] != 0) {
					rc = false;
					break;
				}
			}
			sha->mCorrupted = (sha->mCorrupted == true ||
					   rc == true) ? true : false;
		}
		/* if corrupted then message is too long */
		if (sha->mIndex == 64)
			sha_processblock(sha);
		data++;
	}
}

static int hdcpverify_ksv(const u8 * data, u32 size)
{
	u32 i = 0;
	sha_t sha;

	if ((data == NULL) || (size < (HEADER + SHAMAX))) {
		pr_err("invalid input data");
		return false;
	}

	sha_reset(&sha);
	sha_input(&sha, data, size - SHAMAX);
	if (sha_result(&sha) == false) {
		pr_err("cannot process SHA digest");
		return false;
	}

	for (i = 0; i < SHAMAX; i++) {
		if (data[size - SHAMAX + i] != (u8) (sha.mDigest[i / 4]
				>> ((i % 4) * 8))) {
			pr_err("SHA digest does not match");
			return false;
		}
	}
	return true;
}

static int rk3288_hdcp_ksvsha1(struct hdmi_dev *hdmi_dev)
{
	int rc = 0, value, list, i;
	char bstaus0, bstaus1;
	char *ksvlistbuf;

	hdmi_msk_reg(hdmi_dev, A_KSVMEMCTRL, m_KSV_MEM_REQ, v_KSV_MEM_REQ(1));
	list = 20;
	do {
		value = hdmi_readl(hdmi_dev, A_KSVMEMCTRL);
		udelay(1000);
	} while ((value & m_KSV_MEM_ACCESS) == 0 && --list);

	if ((value & m_KSV_MEM_ACCESS) == 0) {
		pr_err("KSV memory can not access\n");
		rc = -1;
		goto out;
	}

	hdmi_readl(hdmi_dev, HDCP_BSTATUS_0);
	bstaus0 = hdmi_readl(hdmi_dev, HDCP_BSTATUS_0 + 1);
	bstaus1 = hdmi_readl(hdmi_dev, HDCP_BSTATUS_1 + 1);

	if (bstaus0 & m_MAX_DEVS_EXCEEDED) {
		pr_err("m_MAX_DEVS_EXCEEDED\n");
		rc = -1;
		goto out;
	}
	list = bstaus0 & m_DEVICE_COUNT;
	if (list > MAX_DOWNSTREAM_DEVICE_NUM) {
		pr_err("MAX_DOWNSTREAM_DEVICE_NUM\n");
		rc = -1;
		goto out;
	}
	if (bstaus1 & (1 << 3) ) {
		pr_err("MAX_CASCADE_EXCEEDED\n");
		rc = -1;
		goto out;
	}
	value = (list * KSV_LEN) + HEADER + SHAMAX;
	ksvlistbuf = kmalloc(value, GFP_KERNEL);
	if (!ksvlistbuf) {
		pr_err("HDCP: kmalloc ksvlistbuf fail!\n");
		rc = -ENOMEM;
		goto out;
	}
	ksvlistbuf[(list * KSV_LEN)] = bstaus0;
	ksvlistbuf[(list * KSV_LEN) + 1] = bstaus1;
	for (i = 2; i < value; i++) {
		if (i < HEADER)	/* BSTATUS & M0 */
			ksvlistbuf[(list * KSV_LEN) + i] =
				hdmi_readl(hdmi_dev, HDCP_BSTATUS_0 + i + 1);
		else if (i < (HEADER + (list * KSV_LEN))) /* KSV list */
			ksvlistbuf[i - HEADER] =
				hdmi_readl(hdmi_dev, HDCP_BSTATUS_0 + i + 1);
		else /* SHA */
			ksvlistbuf[i] =
				hdmi_readl(hdmi_dev, HDCP_BSTATUS_0 + i + 1);
	}
	if (hdcpverify_ksv(ksvlistbuf, value) == true) {
		rc = 0;
		pr_info("ksv check valid\n");
	} else {
		pr_info("ksv check invalid\n");
		rc = -1;
	}
	kfree(ksvlistbuf);
out:
	hdmi_msk_reg(hdmi_dev, A_KSVMEMCTRL, m_KSV_MEM_REQ, v_KSV_MEM_REQ(0));
	return rc;
}

static void rk3288_hdcp_authentication_2nd(struct hdmi *hdmi)
{
	struct hdmi_dev *hdmi_dev = hdmi->property->priv;

	if (rk3288_hdcp_ksvsha1(hdmi_dev))
		hdmi_msk_reg(hdmi_dev, A_KSVMEMCTRL,
			     m_SHA1_FAIL | m_KSV_UPDATE,
			     v_SHA1_FAIL(1) | v_KSV_UPDATE(1));
	else
		hdmi_msk_reg(hdmi_dev, A_KSVMEMCTRL,
			     m_SHA1_FAIL | m_KSV_UPDATE,
			     v_SHA1_FAIL(0) | v_KSV_UPDATE(1));
}

void rk3288_hdmi_hdcp_isr(struct hdmi_dev *hdmi_dev, int hdcp_int)
{
	pr_info("hdcp_int is 0x%02x\n", hdcp_int);
	
	if (hdcp_int & m_KSVSHA1_CALC_INT) {
		pr_info("hdcp sink is a repeater\n");
		hdmi_submit_work(hdcp->hdmi, HDMI_HDCP_AUTH_2ND, 0, NULL);
	}
	if (hdcp_int & 0x40) {
		pr_info("hdcp check failed\n");
//		pr_info("a_hdcpobs0 %02x\n", hdmi_readl(hdmi_dev, A_HDCPOBS0));
//		pr_info("a_hdcpobs1 %02x\n", hdmi_readl(hdmi_dev, A_HDCPOBS1));
//		pr_info("a_hdcpobs2 %02x\n", hdmi_readl(hdmi_dev, A_HDCPOBS2));
		rk3288_hdmi_hdcp_stop(hdmi_dev->hdmi);
		hdmi_submit_work(hdcp->hdmi, HDMI_ENABLE_HDCP, 0, NULL);
	}
}

static void rk3288_hdcp_load_key(struct hdmi *hdmi, struct hdcp_keys *key)
{
	struct hdmi_dev *hdmi_dev = hdmi->property->priv;
	int i, value;

	/* Disable decryption logic */
	hdmi_writel(hdmi_dev, HDCPREG_RMCTL, 0);
	/* Poll untile DPK write is allowed */
	do {
		value = hdmi_readl(hdmi_dev, HDCPREG_RMSTS);
	} while ((value & m_DPK_WR_OK_STS) == 0);

	/* write unencryped AKSV */
	hdmi_writel(hdmi_dev, HDCPREG_DPK6, 0);
	hdmi_writel(hdmi_dev, HDCPREG_DPK5, 0);
	hdmi_writel(hdmi_dev, HDCPREG_DPK4, key->KSV[4]);
	hdmi_writel(hdmi_dev, HDCPREG_DPK3, key->KSV[3]);
	hdmi_writel(hdmi_dev, HDCPREG_DPK2, key->KSV[2]);
	hdmi_writel(hdmi_dev, HDCPREG_DPK1, key->KSV[1]);
	hdmi_writel(hdmi_dev, HDCPREG_DPK0, key->KSV[0]);
	/* Poll untile DPK write is allowed */
	do {
		value = hdmi_readl(hdmi_dev, HDCPREG_RMSTS);
	} while ((value & m_DPK_WR_OK_STS) == 0);

	if (hdcp->seeds != NULL) {
		hdmi_writel(hdmi_dev, HDCPREG_RMCTL, 1);
		hdmi_writel(hdmi_dev, HDCPREG_SEED1, hdcp->seeds[0]);
		hdmi_writel(hdmi_dev, HDCPREG_SEED0, hdcp->seeds[1]);
	} else {
		hdmi_writel(hdmi_dev, HDCPREG_RMCTL, 0);
	}

	/* write private key */
	for (i = 0; i < HDCP_PRIVATE_KEY_SIZE; i += 7) {
		hdmi_writel(hdmi_dev, HDCPREG_DPK6, key->DeviceKey[i + 6]);
		hdmi_writel(hdmi_dev, HDCPREG_DPK5, key->DeviceKey[i + 5]);
		hdmi_writel(hdmi_dev, HDCPREG_DPK4, key->DeviceKey[i + 4]);
		hdmi_writel(hdmi_dev, HDCPREG_DPK3, key->DeviceKey[i + 3]);
		hdmi_writel(hdmi_dev, HDCPREG_DPK2, key->DeviceKey[i + 2]);
		hdmi_writel(hdmi_dev, HDCPREG_DPK1, key->DeviceKey[i + 1]);
		hdmi_writel(hdmi_dev, HDCPREG_DPK0, key->DeviceKey[i]);

		do {
			value = hdmi_readl(hdmi_dev, HDCPREG_RMSTS);
		} while ((value & m_DPK_WR_OK_STS) == 0);
	}

	pr_info("%s success\n", __func__);
}

static void rk3288_hdcp_load_keys_cb(const struct firmware *fw, void *context)
{
	struct hdmi *hdmi = (struct hdmi *)context;

	if (fw->size < HDCP_KEY_SIZE) {
		pr_err("HDCP: firmware wrong size %d\n", fw->size);
		return;
	}
	hdcp->keys = kmalloc(HDCP_KEY_SIZE, GFP_KERNEL);
	memcpy(hdcp->keys, fw->data, HDCP_KEY_SIZE);

	if (fw->size > HDCP_KEY_SIZE) {
		if ((fw->size - HDCP_KEY_SIZE) < HDCP_KEY_SEED_SIZE) {
			pr_err("HDCP: invalid seed key size\n");
			return;
		}
		hdcp->seeds = kmalloc(HDCP_KEY_SEED_SIZE, GFP_KERNEL);
		if (hdcp->seeds == NULL) {
			pr_err("HDCP: can't allocated space for seed keys\n");
			return;
		}
		memcpy(hdcp->seeds, fw->data + HDCP_KEY_SIZE,
		       HDCP_KEY_SEED_SIZE);
	}
	rk3288_hdcp_load_key(hdmi, hdcp->keys);

}

static void rk3288_hdmi_hdcp_start(struct hdmi *hdmi)
{
	struct hdmi_dev *hdmi_dev = hdmi->property->priv;

	if (!hdcp->enable)
		return;

	hdmi_msk_reg(hdmi_dev, A_HDCPCFG0,
		     m_HDMI_DVI, v_HDMI_DVI(hdmi->edid.sink_hdmi));
	hdmi_writel(hdmi_dev, A_OESSWCFG, 0x40);
	hdmi_msk_reg(hdmi_dev, A_HDCPCFG0,
		     m_ENCRYPT_BYPASS | m_FEATURE11_EN | m_SYNC_RI_CHECK,
		     v_ENCRYPT_BYPASS(0) | v_FEATURE11_EN(0) |
		     v_SYNC_RI_CHECK(1));
	hdmi_msk_reg(hdmi_dev, A_HDCPCFG1,
		     m_ENCRYPT_DISBALE | m_PH2UPSHFTENC,
		     v_ENCRYPT_DISBALE(0) | v_PH2UPSHFTENC(1));
	/* Reset HDCP Engine */
	hdmi_msk_reg(hdmi_dev, A_HDCPCFG1,
		     m_HDCP_SW_RST, v_HDCP_SW_RST(0));

	hdmi_writel(hdmi_dev, A_APIINTMSK, 0x00);
	hdmi_msk_reg(hdmi_dev, A_HDCPCFG0, m_RX_DETECT, v_RX_DETECT(1));

	hdmi_msk_reg(hdmi_dev, MC_CLKDIS,
		     m_HDCPCLK_DISABLE, v_HDCPCLK_DISABLE(0));
	pr_info("%s success\n", __func__);
}

void rk3288_hdmi_hdcp_stop(struct hdmi *hdmi)
{
	struct hdmi_dev *hdmi_dev = hdmi->property->priv;

	if (!hdcp->enable)
		return;

	hdmi_msk_reg(hdmi_dev, MC_CLKDIS,
		     m_HDCPCLK_DISABLE, v_HDCPCLK_DISABLE(1));
	hdmi_writel(hdmi_dev, A_APIINTMSK, 0xff);
	hdmi_msk_reg(hdmi_dev, A_HDCPCFG0, m_RX_DETECT, v_RX_DETECT(0));
	hdmi_msk_reg(hdmi_dev, A_KSVMEMCTRL,
		     m_SHA1_FAIL | m_KSV_UPDATE,
		     v_SHA1_FAIL(0) | v_KSV_UPDATE(0));
}

static ssize_t hdcp_enable_read(struct device *device,
				struct device_attribute *attr, char *buf)
{
	int enable = 0;

	if (hdcp)
		enable = hdcp->enable;

	return snprintf(buf, PAGE_SIZE, "%d\n", enable);
}

static ssize_t hdcp_enable_write(struct device *device,
			   struct device_attribute *attr,
			   const char *buf, size_t count)
{
	int enable;

	if (hdcp == NULL)
		return -EINVAL;

	if (kstrtoint(buf, 0, &enable))
		return -EINVAL;

	if (hdcp->enable != enable) {
		if (!hdcp->enable)
			hdmi_submit_work(hdcp->hdmi, HDMI_ENABLE_HDCP, 0, NULL);
		else
			rk3288_hdmi_hdcp_stop(hdcp->hdmi);
		hdcp->enable =	enable;
	}

	return count;
}
static DEVICE_ATTR(enable, S_IRUGO|S_IWUSR,
		   hdcp_enable_read, hdcp_enable_write);

static ssize_t hdcp_trytimes_read(struct device *device,
				struct device_attribute *attr, char *buf)
{
	int trytimes = 0;

	if (hdcp)
		trytimes = hdcp->retry_times;

	return snprintf(buf, PAGE_SIZE, "%d\n", trytimes);
}

static ssize_t hdcp_trytimes_wrtie(struct device *device,
			   struct device_attribute *attr,
			   const char *buf, size_t count)
{
	int trytimes;

	if (hdcp == NULL)
		return -EINVAL;

	if (kstrtoint(buf, 0, &trytimes))
		return -EINVAL;

	if (hdcp->retry_times != trytimes)
		hdcp->retry_times = trytimes;

	return count;
}
static DEVICE_ATTR(trytimes, S_IRUGO|S_IWUSR,
		   hdcp_trytimes_read, hdcp_trytimes_wrtie);

static int hdcp_init(struct hdmi *hdmi)
{
	int ret;

	mdev.minor = MISC_DYNAMIC_MINOR;
	mdev.name = "hdcp";
	mdev.mode = 0666;
	hdcp = kmalloc(sizeof(struct hdcp), GFP_KERNEL);
	if (!hdcp) {
		pr_err("HDCP: kmalloc fail!\n");
		ret = -ENOMEM;
		goto error0;
	}
	memset(hdcp, 0, sizeof(struct hdcp));
	hdcp->hdmi = hdmi;
	if (misc_register(&mdev)) {
		pr_err("HDCP: Could not add character driver\n");
		ret = HDMI_ERROR_FALSE;
		goto error1;
	}
	ret = device_create_file(mdev.this_device, &dev_attr_enable);
	if (ret) {
		pr_err("HDCP: Could not add sys file enable\n");
		ret = -EINVAL;
		goto error2;
	}
	ret = device_create_file(mdev.this_device, &dev_attr_trytimes);
	if (ret) {
		pr_err("HDCP: Could not add sys file enable\n");
		ret = -EINVAL;
		goto error3;
	}

	ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_NOHOTPLUG,
				  "hdcp", mdev.this_device, GFP_KERNEL,
				  hdmi, rk3288_hdcp_load_keys_cb);

	if (ret < 0) {
		pr_err("HDCP: request_firmware_nowait failed: %d\n", ret);
		goto error4;
	}

	hdmi->ops->hdcp_cb = rk3288_hdmi_hdcp_start;
	hdmi->ops->hdcp_auth2nd = rk3288_hdcp_authentication_2nd;
	return 0;

error4:
	device_remove_file(mdev.this_device, &dev_attr_trytimes);
error3:
	device_remove_file(mdev.this_device, &dev_attr_enable);
error2:
	misc_deregister(&mdev);
error1:
	kfree(hdcp->keys);
	kfree(hdcp->invalidkeys);
	kfree(hdcp);
error0:
	return ret;
}

void rk3288_hdmi_hdcp_init(struct hdmi *hdmi)
{
	if (hdcp == NULL)
		hdcp_init(hdmi);
	else
		rk3288_hdcp_load_key(hdmi, hdcp->keys);
}

