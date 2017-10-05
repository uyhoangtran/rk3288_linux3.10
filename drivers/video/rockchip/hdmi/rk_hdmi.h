#ifndef __ROCKCHIP_HDMI_H__
#define __ROCKCHIP_HDMI_H__

#include <linux/fb.h>
#include <linux/rk_fb.h>
#include <linux/display-sys.h>
#ifdef CONFIG_SWITCH
#include <linux/switch.h>
#endif

#define HDMI_VIDEO_NORMAL				(0 << 8)
#define HDMI_VIDEO_EXT					(1 << 8)
#define HDMI_VIDEO_3D					(2 << 8)
#define HDMI_VIDEO_DVI					(3 << 8)
#define HDMI_VIC_MASK					(0xFF)
#define HDMI_TYPE_MASK					(0xFF << 8)
#define HDMI_MAX_ID					4

/* HDMI video information code according CEA-861-F */
enum hdmi_video_infomation_code {
	HDMI_640x480P_60HZ = 1,
	HDMI_720x480P_60HZ_4_3,
	HDMI_720x480P_60HZ_16_9,
	HDMI_1280x720P_60HZ,
	HDMI_1920x1080I_60HZ,		/*5*/
	HDMI_720x480I_60HZ_4_3,
	HDMI_720x480I_60HZ_16_9,
	HDMI_720x240P_60HZ_4_3,
	HDMI_720x240P_60HZ_16_9,
	HDMI_2880x480I_60HZ_4_3,	/*10*/
	HDMI_2880x480I_60HZ_16_9,
	HDMI_2880x240P_60HZ_4_3,
	HDMI_2880x240P_60HZ_16_9,
	HDMI_1440x480P_60HZ_4_3,
	HDMI_1440x480P_60HZ_16_9,	/*15*/
	HDMI_1920x1080P_60HZ,
	HDMI_720x576P_50HZ_4_3,
	HDMI_720x576P_50HZ_16_9,
	HDMI_1280x720P_50HZ,
	HDMI_1920x1080I_50HZ,		/*20*/
	HDMI_720x576I_50HZ_4_3,
	HDMI_720x576I_50HZ_16_9,
	HDMI_720x288P_50HZ_4_3,
	HDMI_720x288P_50HZ_16_9,
	HDMI_2880x576I_50HZ_4_3,	/*25*/
	HDMI_2880x576I_50HZ_16_9,
	HDMI_2880x288P_50HZ_4_3,
	HDMI_2880x288P_50HZ_16_9,
	HDMI_1440x576P_50HZ_4_3,
	HDMI_1440x576P_50HZ_16_9,	/*30*/
	HDMI_1920x1080P_50HZ,
	HDMI_1920x1080P_24HZ,
	HDMI_1920x1080P_25HZ,
	HDMI_1920x1080P_30HZ,
	HDMI_2880x480P_60HZ_4_3,	/*35*/
	HDMI_2880x480P_60HZ_16_9,
	HDMI_2880x576P_50HZ_4_3,
	HDMI_2880x576P_50HZ_16_9,
	HDMI_1920x1080I_50HZ_1250,	/* V Line 1250 total*/
	HDMI_1920x1080I_100HZ,		/*40*/
	HDMI_1280x720P_100HZ,
	HDMI_720x576P_100HZ_4_3,
	HDMI_720x576P_100HZ_16_9,
	HDMI_720x576I_100HZ_4_3,
	HDMI_720x576I_100HZ_16_9,	/*45*/
	HDMI_1920x1080I_120HZ,
	HDMI_1280x720P_120HZ,
	HDMI_720x480P_120HZ_4_3,
	HDMI_720x480P_120HZ_16_9,
	HDMI_720x480I_120HZ_4_3,	/*50*/
	HDMI_720x480I_120HZ_16_9,
	HDMI_720x576P_200HZ_4_3,
	HDMI_720x576P_200HZ_16_9,
	HDMI_720x576I_200HZ_4_3,
	HDMI_720x576I_200HZ_16_9,	/*55*/
	HDMI_720x480P_240HZ_4_3,
	HDMI_720x480P_240HZ_16_9,
	HDMI_720x480I_240HZ_4_3,
	HDMI_720x480I_240HZ_16_9,
	HDMI_1280x720P_24HZ,		/*60*/
	HDMI_1280x720P_25HZ,
	HDMI_1280x720P_30HZ,
	HDMI_1920x1080P_120HZ,
	HDMI_1920x1080P_100HZ,
	HDMI_1280x720P_24HZ_4_3,	/*65*/
	HDMI_1280x720P_25HZ_4_3,
	HDMI_1280x720P_30HZ_4_3,
	HDMI_1280x720P_50HZ_4_3,
	HDMI_1280x720P_60HZ_4_3,
	HDMI_1280x720P_100HZ_4_3,	/*70*/
	HDMI_1280x720P_120HZ_4_3,
	HDMI_1920x1080P_24HZ_4_3,
	HDMI_1920x1080P_25HZ_4_3,
	HDMI_1920x1080P_30HZ_4_3,
	HDMI_1920x1080P_50HZ_4_3,	/*75*/
	HDMI_1920x1080P_60HZ_4_3,
	HDMI_1920x1080P_100HZ_4_3,
	HDMI_1920x1080P_120HZ_4_3,
	HDMI_1680x720P_24HZ,
	HDMI_1680x720P_25HZ,		/*80*/
	HDMI_1680x720P_30HZ,
	HDMI_1680x720P_50HZ,
	HDMI_1680x720P_60HZ,
	HDMI_1680x720P_100HZ,
	HDMI_1680x720P_120HZ,		/*85*/
	HDMI_2560x1080P_24HZ,
	HDMI_2560x1080P_25HZ,
	HDMI_2560x1080P_30HZ,
	HDMI_2560x1080P_50HZ,
	HDMI_2560x1080P_60HZ,		/*90*/
	HDMI_2560x1080P_100HZ,
	HDMI_2560x1080P_120HZ,
	HDMI_3840x2160P_24HZ,
	HDMI_3840x2160P_25HZ,
	HDMI_3840x2160P_30HZ,		/*95*/
	HDMI_3840x2160P_50HZ,
	HDMI_3840x2160P_60HZ,
	HDMI_4096x2160P_24HZ,
	HDMI_4096x2160P_25HZ,
	HDMI_4096x2160P_30HZ,		/*100*/
	HDMI_4096x2160P_50HZ,
	HDMI_4096x2160P_60HZ,
	HDMI_3840x2160P_24HZ_4_3,
	HDMI_3840x2160P_25HZ_4_3,
	HDMI_3840x2160P_30HZ_4_3,	/*105*/
	HDMI_3840x2160P_50HZ_4_3,
	HDMI_3840x2160P_60HZ_4_3,
};

/* HDMI Extended Resolution */
enum {
	HDMI_VIC_4Kx2K_30Hz = 1,
	HDMI_VIC_4Kx2K_25Hz,
	HDMI_VIC_4Kx2K_24Hz,
	HDMI_VIC_4Kx2K_24Hz_SMPTE
};

/* HDMI Video Format */
enum {
	HDMI_VIDEO_FORMAT_NORMAL = 0,
	HDMI_VIDEO_FORMAT_4Kx2K,
	HDMI_VIDEO_FORMAT_3D,
};

/* HDMI 3D type */
enum {
	HDMI_3D_NONE = -1,
	HDMI_3D_FRAME_PACKING = 0,
	HDMI_3D_TOP_BOOTOM = 6,
	HDMI_3D_SIDE_BY_SIDE_HALF = 8,
};

/* HDMI Video Data Color Mode */
enum hdmi_video_color_mode {
	HDMI_COLOR_AUTO	= 0,
	HDMI_COLOR_RGB_0_255,
	HDMI_COLOR_RGB_16_235,
	HDMI_COLOR_YCbCr444,
	HDMI_COLOR_YCbCr422,
	HDMI_COLOR_YCbCr420
};

/* HDMI Video Data Color Depth */
enum hdmi_deep_color {
	HDMI_DEPP_COLOR_AUTO = 0,
	HDMI_DEEP_COLOR_Y444 = 0x1,
	HDMI_DEEP_COLOR_30BITS = 0x2,
	HDMI_DEEP_COLOR_36BITS = 0x4,
	HDMI_DEEP_COLOR_48BITS = 0x8,
};

/* HDMI Audio Type */
enum hdmi_audio_type {
	HDMI_AUDIO_NLPCM = 0,
	HDMI_AUDIO_LPCM = 1,
	HDMI_AUDIO_AC3,
	HDMI_AUDIO_MPEG1,
	HDMI_AUDIO_MP3,
	HDMI_AUDIO_MPEG2,
	HDMI_AUDIO_AAC_LC,		/*AAC */
	HDMI_AUDIO_DTS,
	HDMI_AUDIO_ATARC,
	HDMI_AUDIO_DSD,			/* One bit Audio */
	HDMI_AUDIO_E_AC3,
	HDMI_AUDIO_DTS_HD,
	HDMI_AUDIO_MLP,
	HDMI_AUDIO_DST,
	HDMI_AUDIO_WMA_PRO
};

/* HDMI Audio Sample Rate */
enum hdmi_audio_samplerate {
	HDMI_AUDIO_FS_32000  = 0x1,
	HDMI_AUDIO_FS_44100  = 0x2,
	HDMI_AUDIO_FS_48000  = 0x4,
	HDMI_AUDIO_FS_88200  = 0x8,
	HDMI_AUDIO_FS_96000  = 0x10,
	HDMI_AUDIO_FS_176400 = 0x20,
	HDMI_AUDIO_FS_192000 = 0x40
};

/* HDMI Audio Word Length */
enum hdmi_audio_word_length {
	HDMI_AUDIO_WORD_LENGTH_16bit = 0x1,
	HDMI_AUDIO_WORD_LENGTH_20bit = 0x2,
	HDMI_AUDIO_WORD_LENGTH_24bit = 0x4
};

/* HDMI Hotplug Status */
enum hdmi_hotpulg_status {
	HDMI_HPD_REMOVED = 0,		/* HDMI is disconnected */
	HDMI_HPD_INSERT,		/* HDMI is connected, but HDP is low
					or TMDS link is not pull up to 3.3V*/
	HDMI_HPD_ACTIVED		/* HDMI is connected, all singnal
					  is normal */
};

enum hdmi_mute_status {
	HDMI_AV_UNMUTE = 0,
	HDMI_VIDEO_MUTE = 0x1,
	HDMI_AUDIO_MUTE = 0x2,
};

/* HDMI Error Code */
enum hdmi_error_code {
	HDMI_ERROR_SUCESS = 0,
	HDMI_ERROR_FALSE,
	HDMI_ERROR_I2C,
	HDMI_ERROR_EDID,
};

/* HDMI Video Timing */
struct hdmi_video_timing {
	struct fb_videomode mode;	/* Video timing*/
	unsigned int vic;		/* Video information code*/
	unsigned int vic_2nd;
	unsigned int pixelrepeat;	/* Video pixel repeat rate*/
	unsigned int interface;		/* Video input interface*/
};

/* HDMI Video Parameters */
struct hdmi_video {
	unsigned int vic;		/* Video information code*/
	unsigned int color_input;	/* Input video color mode*/
	unsigned int color_output;	/* Output video color mode*/
	unsigned int color_output_depth;/* Output video Color Depth*/
	unsigned int sink_hdmi;		/* Output signal is DVI or HDMI*/
	unsigned int format_3d;		/* Output 3D mode*/
};

/* HDMI Audio Parameters */
struct hdmi_audio {
	u32	type;			/*Audio type*/
	u32	channel;		/*Audio channel number*/
	u32	rate;			/*Audio sampling rate*/
	u32	word_length;		/*Audio data word length*/
};

/* HDMI EDID Information */
struct hdmi_edid {
	unsigned char sink_hdmi;	/*HDMI display device flag*/
	unsigned char ycbcr444;		/*Display device support YCbCr444*/
	unsigned char ycbcr422;		/*Display device support YCbCr422*/
	unsigned char ycbcr420;		/*Display device support YCbCr420*/
	unsigned char deepcolor;	/*bit3:DC_48bit; bit2:DC_36bit;
					  bit1:DC_30bit; bit0:DC_Y444;*/
	unsigned int  cecaddress;	/*CEC physical address*/
	unsigned int  maxtmdsclock;	/*Max supported tmds clock*/
	unsigned char fields_present;	/*bit7: latency
					  bit6: i_lantency
					  bit5: hdmi_video*/
	unsigned char video_latency;
	unsigned char audio_latency;
	unsigned char interlaced_video_latency;
	unsigned char interlaced_audio_latency;
	/* for hdmi 2.0 */
	unsigned char hf_vsdb_version;
	unsigned char scdc_present;
	unsigned char rr_capable;
	unsigned char lte_340mcsc_scramble;
	unsigned char independent_view;
	unsigned char dual_view;
	unsigned char osd_disparity_3d;

	struct fb_monspecs	*specs;	/*Device spec*/
	struct list_head modelist;	/*Device supported display mode list*/
	struct hdmi_audio *audio;	/*Device supported audio info*/
	unsigned int  audio_num;	/*Device supported audio type number*/
};

struct hdmi;

struct hdmi_ops {
	int (*enable)(struct hdmi *);
	int (*disable)(struct hdmi *);
	int (*getStatus)(struct hdmi *);
	int (*insert)(struct hdmi *);
	int (*remove)(struct hdmi *);
	int (*getEdid)(struct hdmi *, int, unsigned char *);
	int (*setVideo)(struct hdmi *, struct hdmi_video *);
	int (*setAudio)(struct hdmi *, struct hdmi_audio *);
	int (*setMute)(struct hdmi *, int);
	int (*setVSI)(struct hdmi *, unsigned char, unsigned char);
	int (*setCEC)(struct hdmi *);
	/* call back for hdcp operatoion */
	void (*hdcp_cb)(struct hdmi *);
	void (*hdcp_auth2nd)(struct hdmi*);
	void (*hdcp_irq_cb)(int);
	int (*hdcp_power_on_cb)(void);
	void (*hdcp_power_off_cb)(void);
};

struct hdmi_property {
	char *name;
	int videosrc;
	int display;
	void *priv;
};

/* HDMI Information */
struct hdmi {
	int id;					/*HDMI id*/
	struct device	*dev;			/*HDMI device*/
	struct rk_lcdc_driver *lcdc;		/*HDMI linked lcdc*/
	struct rk_display_device *ddev;		/*Registered display device*/
	#ifdef CONFIG_SWITCH
	struct switch_dev	switchdev;	/*Registered switch device*/
	#endif

	struct hdmi_property *property;
	struct hdmi_ops *ops;

	struct mutex lock;
	struct workqueue_struct *workqueue;

	bool uboot;	/* if true, HDMI is initialized in uboot*/

	int hotplug;	/* hot plug status*/
	int autoset;	/* if true, auto set hdmi output mode according EDID.*/
	int mute;	/* HDMI display status:
			   2 means mute audio,
			   1 means mute display;
			   0 is unmute*/
	int colordepth;
	int colormode;

	struct hdmi_edid edid;		/* EDID information*/
	int enable;			/* Enable flag*/
	int sleep;			/* Sleep flag*/
	int vic;			/* HDMI output video information code*/
	int mode_3d;			/* HDMI output video 3d mode*/
	struct hdmi_audio audio;	/* HDMI output audio information.*/
	int cecenable;			/*HDMI CEC switch*/
	int edidread;
};

/* HDMI EDID Block Size */
#define HDMI_EDID_BLOCK_SIZE	128

/* SCDC Registers */
#define SCDC_SINK_VER		0x01	/* sink version		*/
#define SCDC_SOURCE_VER		0x02	/* source version	*/
#define SCDC_UPDATE_0		0x10	/* Update_0		*/
#define SCDC_UPDATE_1		0x11	/* Update_1		*/
#define SCDC_UPDATE_RESERVED	0x12	/* 0x12-0x1f - Reserved */
#define SCDC_TMDS_CONFIG	0x20	/* TMDS_Config   */
#define SCDC_SCRAMBLER_STAT	0x21	/* Scrambler_Status   */
#define SCDC_CONFIG_0		0x30	/* Config_0           */
#define SCDC_CONFIG_RESERVED	0x31	/* 0x31-0x3f - Reserved */
#define SCDC_STATUS_FLAG_0	0x40	/* Status_Flag_0        */
#define SCDC_STATUS_FLAG_1	0x41	/* Status_Flag_1        */
#define SCDC_STATUS_RESERVED	0x42	/* 0x42-0x4f - Reserved */
#define SCDC_ERR_DET_0_L	0x50	/* Err_Det_0_L          */
#define SCDC_ERR_DET_0_H	0x51	/* Err_Det_0_H          */
#define SCDC_ERR_DET_1_L	0x52	/* Err_Det_1_L          */
#define SCDC_ERR_DET_1_H	0x53	/* Err_Det_1_H          */
#define SCDC_ERR_DET_2_L	0x54	/* Err_Det_2_L          */
#define SCDC_ERR_DET_2_H	0x55	/* Err_Det_2_H          */
#define SCDC_ERR_DET_CHKSUM	0x56	/* Err_Det_Checksum     */
#define SCDC_TEST_CFG_0		0xc0	/* Test_config_0        */
#define SCDC_TEST_RESERVED	0xc1	/* 0xc1-0xcf		*/
#define SCDC_MAN_OUI_3RD	0xd0	/* Manufacturer IEEE OUI,
					   Third Octet */
#define SCDC_MAN_OUI_2ND	0xd1	/* Manufacturer IEEE OUI,
					   Second Octet */
#define SCDC_MAN_OUI_1ST	0xd2	/* Manufacturer IEEE OUI,
					   First Octet */
#define SCDC_DEVICE_ID		0xd3	/* 0xd3-0xdd - Device ID            */
#define SCDC_MAN_SPECIFIC	0xde	/* 0xde-0xff - ManufacturerSpecific */

/* Event source */
#define HDMI_SRC_SHIFT		8
#define HDMI_SYSFS_SRC		(0x1 << HDMI_SRC_SHIFT)
#define HDMI_SUSPEND_SRC	(0x2 << HDMI_SRC_SHIFT)
#define HDMI_IRQ_SRC		(0x4 << HDMI_SRC_SHIFT)
#define HDMI_WORKQUEUE_SRC	(0x8 << HDMI_SRC_SHIFT)

/* Event */
#define HDMI_ENABLE_CTL			(HDMI_SYSFS_SRC		| 0)
#define HDMI_DISABLE_CTL		(HDMI_SYSFS_SRC		| 1)
#define HDMI_SUSPEND_CTL		(HDMI_SUSPEND_SRC	| 2)
#define HDMI_RESUME_CTL			(HDMI_SUSPEND_SRC	| 3)
#define HDMI_HPD_CHANGE			(HDMI_IRQ_SRC		| 4)
#define HDMI_SET_VIDEO			(HDMI_SYSFS_SRC		| 5)
#define HDMI_SET_AUDIO			(HDMI_SYSFS_SRC		| 6)
#define HDMI_SET_3D			(HDMI_SYSFS_SRC		| 7)
#define HDMI_MUTE_AUDIO			(HDMI_SYSFS_SRC		| 8)
#define HDMI_UNMUTE_AUDIO		(HDMI_SYSFS_SRC		| 9)
#define HDMI_SET_COLOR			(HDMI_SYSFS_SRC		| 10)
#define HDMI_ENABLE_HDCP		(HDMI_SYSFS_SRC		| 11)
#define HDMI_HDCP_AUTH_2ND		(HDMI_IRQ_SRC		| 12)

#define HDMI_DEFAULT_SCALE		95
#define HDMI_AUTO_CONFIG		true

/* HDMI default vide mode */
#define HDMI_VIDEO_DEFAULT_MODE			HDMI_1280x720P_60HZ
						/*HDMI_1920x1080P_60HZ*/
#define HDMI_VIDEO_DEFAULT_COLORMODE		HDMI_COLOR_AUTO
#define HDMI_VIDEO_DEFAULT_COLORDEPTH		HDMI_DEPP_COLOR_AUTO

/* HDMI default audio parameter */
#define HDMI_AUDIO_DEFAULT_TYPE			HDMI_AUDIO_LPCM
#define HDMI_AUDIO_DEFAULT_CHANNEL		2
#define HDMI_AUDIO_DEFAULT_RATE			HDMI_AUDIO_FS_44100
#define HDMI_AUDIO_DEFAULT_WORDLENGTH	HDMI_AUDIO_WORD_LENGTH_16bit

#ifdef DEBUG
#define DBG(format, ...) \
		pr_info("HDMI: " format "\n", ## __VA_ARGS__)
#else
#define DBG(format, ...)
#endif

struct hdmi *hdmi_register(struct hdmi_property *property,
	struct hdmi_ops *ops);
void hdmi_unregister(struct hdmi *hdmi);
struct delayed_work *hdmi_submit_work(struct hdmi *hdmi,
	int event, int delay, void *data);
void hdmi_suspend(struct hdmi *hdmi);

struct rk_display_device *hdmi_register_display_sysfs(struct hdmi *hdmi,
	struct device *parent);
void hdmi_unregister_display_sysfs(struct hdmi *hdmi);

int hdmi_edid_parse_base(unsigned char *buf,
	int *extend_num, struct hdmi_edid *pedid);
int hdmi_edid_parse_extensions(unsigned char *buf,
	struct hdmi_edid *pedid);
int hdmi_edid_parse_head(unsigned char *buf,
			 int *extend_num, struct hdmi_edid *pedid);

void hdmi_init_modelist(struct hdmi *hdmi);
int hdmi_set_lcdc(struct hdmi *hdmi);
int hdmi_ouputmode_select(struct hdmi *hdmi, int edid_ok);
int hdmi_add_vic(int vic, struct list_head *head);
int hdmi_find_best_mode(struct hdmi *hdmi, int vic);
int hdmi_videomode_to_vic(struct fb_videomode *vmode);
const struct fb_videomode *hdmi_vic_to_videomode(int vic);
const struct hdmi_video_timing *hdmi_vic2timing(int vic);
int hdmi_config_audio(struct hdmi_audio *audio);

#endif
