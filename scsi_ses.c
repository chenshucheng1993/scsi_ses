/*
 *
 *  Copyright (C) 2004 Douglas Gilbert and Zacharia Mathew
 *       Email:   <dgilbert@interlog.com>  <sakimathew@yahoo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * scsi_ses.c  Source for scsi_ses target enclosure simulator for
 * lk 2.6 series.
 */

#include <linux/config.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/smp_lock.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>

#include <linux/blkdev.h>
#include "scsi.h"
#include <scsi/scsi_host.h>
#include <scsi/scsicam.h>

#include <linux/stat.h>

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#endif

#include "scsi_logging.h"
#include "scsi_ses.h"

#define SCSI_SES_VERSION "1.02"
static const char * scsi_ses_version_date = "20050211";

/* Additional Sense Code (ASC) used */
#define NO_ADDED_SENSE 0x0
#define UNRECOVERED_READ_ERR 0x11
#define INVALID_OPCODE 0x20
#define ADDR_OUT_OF_RANGE 0x21
#define INVALID_FIELD_IN_CDB 0x24
#define POWERON_RESET 0x29
#define SAVING_PARAMS_UNSUP 0x39
#define THRESHHOLD_EXCEEDED 0x5d

#define SSES_TAGGED_QUEUING 0 /* 0 | MSG_SIMPLE_TAG | MSG_ORDERED_TAG */

#define DEF_DELAY   1
#define DEF_DEV_SIZE_MB   8
#define DEF_EVERY_NTH   0
#define DEF_NUM_PARTS   0
#define DEF_OPTS   0
#define DEF_SCSI_LEVEL   5    /* INQUIRY, byte2 [5->SPC-3] */
#define DEF_D_SENSE   0
#define DEF_SES_ONLY   0

/* bit mask values for scsi_ses_opts */
#define SCSI_SES_OPT_NOISE   1

/* If REPORT LUNS has luns >= 256 it can choose "flat space" (value 1)
 * or "peripheral device" addressing (value 0) */
#define SAM2_LUN_ADDRESS_METHOD 0

static int scsi_ses_delay = DEF_DELAY;
static int scsi_ses_dev_size_mb = DEF_DEV_SIZE_MB;
static int scsi_ses_every_nth = DEF_EVERY_NTH;
static int scsi_ses_num_parts = DEF_NUM_PARTS;
static int scsi_ses_opts = DEF_OPTS;
static int scsi_ses_scsi_level = DEF_SCSI_LEVEL;
static int scsi_ses_dsense = DEF_D_SENSE;
static int scsi_ses_ses_only = DEF_SES_ONLY;

static int scsi_ses_max_luns = 1;
static int scsi_ses_num_tgts = 1;
static int scsi_ses_add_host = 1;


#define DEV_READONLY(TGT)      (0)
#define DEV_REMOVEABLE(TGT)    (0)

static unsigned long sses_store_size;	/* in bytes */
static sector_t sses_capacity;	/* in sectors */

/* old BIOS stuff, kernel may get rid of them but some mode sense pages
   may still need them */
static int sses_heads;		/* heads per disk */
static int sses_cylinders_per;	/* cylinders per surface */
static int sses_sectors_per;		/* sectors per cylinder */

/* default sector size is 512 bytes, 2**9 bytes */
#define POW2_SECT_SIZE 9
#define SECT_SIZE (1 << POW2_SECT_SIZE)
#define SECT_SIZE_PER(TGT) SECT_SIZE

#define SSES_MAX_PARTS 4

#define SSES_SENSE_LEN 32

struct sses_dev_info {
	struct list_head dev_list;
	unsigned char sense_buff[SSES_SENSE_LEN];	/* weak nexus */
	unsigned int channel;
	unsigned int target;
	unsigned int lun;
	struct sses_host_info *sdbg_host;
	char reset;
	char used;
};

struct sses_host_info {
	struct list_head host_list;
	struct Scsi_Host *shost;
	struct device dev;
	struct list_head dev_info_list;
};

#define to_sses_host(d)	\
	container_of(d, struct sses_host_info, dev)

static LIST_HEAD(sses_host_list);
static DEFINE_SPINLOCK(sses_host_list_lock);

typedef void (* done_funct_t) (struct scsi_cmnd *);

struct sses_queued_cmd {
	int in_use;
	struct timer_list cmnd_timer;
	done_funct_t done_funct;
	struct scsi_cmnd * a_cmnd;
	int scsi_result;
};
static struct sses_queued_cmd queued_arr[SCSI_SES_CANQUEUE];

static int scsi_ses_slave_alloc(struct scsi_device *);
static int scsi_ses_slave_configure(struct scsi_device *);
static void scsi_ses_slave_destroy(struct scsi_device *);
static int scsi_ses_queuecommand(struct scsi_cmnd *,
                                   void (*done) (struct scsi_cmnd *));
static int scsi_ses_ioctl(struct scsi_device *, int, void __user *);
static int scsi_ses_biosparam(struct scsi_device *, struct block_device *,
                sector_t, int[]);
static int scsi_ses_abort(struct scsi_cmnd *);
static int scsi_ses_bus_reset(struct scsi_cmnd *);
static int scsi_ses_device_reset(struct scsi_cmnd *);
static int scsi_ses_host_reset(struct scsi_cmnd *);
static const char * scsi_ses_info(struct Scsi_Host *);

static Scsi_Host_Template sses_driver_template = {
	.name =			"SCSI SES",
	.info =			scsi_ses_info,
	.slave_alloc =		scsi_ses_slave_alloc,
	.slave_configure =	scsi_ses_slave_configure,
	.slave_destroy =	scsi_ses_slave_destroy,
	.ioctl =		scsi_ses_ioctl,
	.queuecommand =		scsi_ses_queuecommand,
	.eh_abort_handler =	scsi_ses_abort,
	.eh_bus_reset_handler = scsi_ses_bus_reset,
	.eh_device_reset_handler = scsi_ses_device_reset,
	.eh_host_reset_handler = scsi_ses_host_reset,
	.bios_param =		scsi_ses_biosparam,
	.can_queue =		SCSI_SES_CANQUEUE,
	.this_id =		7,
	.sg_tablesize =		64,
	.cmd_per_lun =		3,
	.max_sectors =		4096,
	.unchecked_isa_dma = 	0,
	.use_clustering = 	DISABLE_CLUSTERING,
	.module =		THIS_MODULE,
};

static unsigned char * fake_storep;	/* ramdisk storage */

static int num_aborts = 0;
static int num_dev_resets = 0;
static int num_bus_resets = 0;
static int num_host_resets = 0;

static DEFINE_SPINLOCK(queued_arr_lock);
static DEFINE_RWLOCK(atomic_rw);

static char sses_proc_name[] = "scsi_ses";

static int sses_driver_probe(struct device *);
static int sses_driver_remove(struct device *);
static struct bus_type spseudo_lld_bus;

static struct device_driver sses_driverfs_driver = {
	.name 		= sses_proc_name,
	.bus		= &spseudo_lld_bus,
	.probe          = sses_driver_probe,
	.remove         = sses_driver_remove,
};

static const int check_condition_result =
		(DRIVER_SENSE << 24) | SAM_STAT_CHECK_CONDITION;

/* function declarations */
static int resp_inquiry(struct scsi_cmnd * SCpnt, int target,
			struct sses_dev_info * devip);
static int resp_requests(struct scsi_cmnd * SCpnt,
			 struct sses_dev_info * devip);
static int resp_readcap(struct scsi_cmnd * SCpnt,
			struct sses_dev_info * devip);
static int resp_mode_sense(struct scsi_cmnd * SCpnt, int target,
			   struct sses_dev_info * devip);
static int resp_read(struct scsi_cmnd * SCpnt, int upper_blk, int block,
		     int num, struct sses_dev_info * devip);
static int resp_write(struct scsi_cmnd * SCpnt, int upper_blk, int block,
		      int num, struct sses_dev_info * devip);
static int resp_report_luns(struct scsi_cmnd * SCpnt,
			    struct sses_dev_info * devip);
static int fill_from_dev_buffer(struct scsi_cmnd * scp, unsigned char * arr,
                                int arr_len);
static int fetch_to_dev_buffer(struct scsi_cmnd * scp, unsigned char * arr,
                               int max_arr_len);
static void timer_intr_handler(unsigned long);
static struct sses_dev_info * devInfoReg(struct scsi_device * sdev);
static void mk_sense_buffer(struct sses_dev_info * devip, int key,
			    int asc, int asq);
static int check_reset(struct scsi_cmnd * SCpnt,
		       struct sses_dev_info * devip);
static int check_is_disk(struct scsi_cmnd * SCpnt,
                         struct sses_dev_info * devip);
static int schedule_resp(struct scsi_cmnd * cmnd,
			 struct sses_dev_info * devip,
			 done_funct_t done, int scsi_result, int delta_jiff);
static void __init sses_build_parts(unsigned char * ramp);
static void __init init_all_queued(void);
static void stop_all_queued(void);
static int stop_queued_cmnd(struct scsi_cmnd * cmnd);
static int inquiry_evpd_83(unsigned char * arr, int dev_id_num,
                           const char * dev_id_str, int dev_id_str_len);
static void do_create_driverfs_files(void);
static void do_remove_driverfs_files(void);

static int receive_diagnostic_command(Scsi_Cmnd *cmd_arg,
                                      struct sses_dev_info *devip);
static int resp_send_diag(Scsi_Cmnd *cmd_arg,
                          struct sses_dev_info *devip);

static int initialize_ses_dev( struct ses_dev *ses_device);

static int sses_add_adapter(void);
static void sses_remove_adapter(void);

static struct device spseudo_primary;
static struct bus_type spseudo_lld_bus;

static struct ses_dev ses_device;


static
int scsi_ses_queuecommand(struct scsi_cmnd * SCpnt, done_funct_t done)
{
	unsigned char *cmd = (unsigned char *) SCpnt->cmnd;
	int block, upper_blk, num, k;
	int errsts = 0;
	int target = SCpnt->device->id;
	struct sses_dev_info * devip = NULL;
	int inj_recovered = 0;

	if (done == NULL)
		return 0;	/* assume mid level reprocessing command */

	if ((SCSI_SES_OPT_NOISE & scsi_ses_opts) && cmd) {
		printk(KERN_INFO "scsi_ses: cmd ");
		for (k = 0, num = SCpnt->cmd_len; k < num; ++k)
			printk("%02x ", (int)cmd[k]);
		printk("\n");
	}
        if(target == sses_driver_template.this_id) {
		printk(KERN_INFO "scsi_ses: initiator's id used as "
		       "target!\n");
		return schedule_resp(SCpnt, NULL, done,
				     DID_NO_CONNECT << 16, 0);
        }

	if (SCpnt->device->lun >= scsi_ses_max_luns)
		return schedule_resp(SCpnt, NULL, done,
				     DID_NO_CONNECT << 16, 0);
	devip = devInfoReg(SCpnt->device);
	if (NULL == devip)
		return schedule_resp(SCpnt, NULL, done,
				     DID_NO_CONNECT << 16, 0);

	switch (*cmd) {
	case INQUIRY:     /* mandatory, ignore unit attention */
		errsts = resp_inquiry(SCpnt, target, devip);
		break;
	case REQUEST_SENSE:	/* mandatory, ignore unit attention */
		errsts = resp_requests(SCpnt, devip);
		break;
	case REZERO_UNIT:	/* actually this is REWIND for SSC */
	case START_STOP:
		errsts = check_is_disk(SCpnt, devip);
		break;
	case ALLOW_MEDIUM_REMOVAL:
		if ((errsts = check_is_disk(SCpnt, devip)))
			break;
		if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
			printk(KERN_INFO "scsi_ses: Medium removal %s\n",
			        cmd[4] ? "inhibited" : "enabled");
		break;
	case SEND_DIAGNOSTIC:     /* mandatory */
		if ((errsts = check_reset(SCpnt, devip)))
			break;
		if (cmd[1] & 0x10)
                        errsts = resp_send_diag(SCpnt, devip);
                break;
        case RECEIVE_DIAGNOSTIC:
                errsts = receive_diagnostic_command(SCpnt, devip);
                break;
	case TEST_UNIT_READY:     /* mandatory */
		errsts = check_reset(SCpnt, devip);
		break;
        case RESERVE:
		errsts = check_is_disk(SCpnt, devip);
                break;
        case RESERVE_10:
		errsts = check_is_disk(SCpnt, devip);
                break;
        case RELEASE:
		errsts = check_is_disk(SCpnt, devip);
                break;
        case RELEASE_10:
		errsts = check_is_disk(SCpnt, devip);
                break;
	case READ_CAPACITY:
		errsts = resp_readcap(SCpnt, devip);
		break;
	case READ_16:
	case READ_12:
	case READ_10:
	case READ_6:
		if ((errsts = check_is_disk(SCpnt, devip)))
			break;
		upper_blk = 0;
		if ((*cmd) == READ_16) {
			upper_blk = cmd[5] + (cmd[4] << 8) +
				    (cmd[3] << 16) + (cmd[2] << 24);
			block = cmd[9] + (cmd[8] << 8) +
				(cmd[7] << 16) + (cmd[6] << 24);
			num = cmd[13] + (cmd[12] << 8) +
				(cmd[11] << 16) + (cmd[10] << 24);
		} else if ((*cmd) == READ_12) {
			block = cmd[5] + (cmd[4] << 8) +
				(cmd[3] << 16) + (cmd[2] << 24);
			num = cmd[9] + (cmd[8] << 8) +
				(cmd[7] << 16) + (cmd[6] << 24);
		} else if ((*cmd) == READ_10) {
			block = cmd[5] + (cmd[4] << 8) +
				(cmd[3] << 16) + (cmd[2] << 24);
			num = cmd[8] + (cmd[7] << 8);
		} else {
			block = cmd[3] + (cmd[2] << 8) +
				((cmd[1] & 0x1f) << 16);
			num = cmd[4];
		}
		errsts = resp_read(SCpnt, upper_blk, block, num, devip);
		if (inj_recovered && (0 == errsts)) {
			mk_sense_buffer(devip, RECOVERED_ERROR,
					THRESHHOLD_EXCEEDED, 0);
			errsts = check_condition_result;
		}
		break;
	case REPORT_LUNS:	/* mandatory, ignore unit attention */
		errsts = resp_report_luns(SCpnt, devip);
		break;
	case VERIFY:		/* 10 byte SBC-2 command */
		errsts = check_is_disk(SCpnt, devip);
		break;
	case WRITE_16:
	case WRITE_12:
	case WRITE_10:
	case WRITE_6:
		if ((errsts = check_is_disk(SCpnt, devip)))
			break;
		upper_blk = 0;
		if ((*cmd) == WRITE_16) {
			upper_blk = cmd[5] + (cmd[4] << 8) +
				    (cmd[3] << 16) + (cmd[2] << 24);
			block = cmd[9] + (cmd[8] << 8) +
				(cmd[7] << 16) + (cmd[6] << 24);
			num = cmd[13] + (cmd[12] << 8) +
				(cmd[11] << 16) + (cmd[10] << 24);
		} else if ((*cmd) == WRITE_12) {
			block = cmd[5] + (cmd[4] << 8) +
				(cmd[3] << 16) + (cmd[2] << 24);
			num = cmd[9] + (cmd[8] << 8) +
				(cmd[7] << 16) + (cmd[6] << 24);
		} else if ((*cmd) == WRITE_10) {
			block = cmd[5] + (cmd[4] << 8) +
				(cmd[3] << 16) + (cmd[2] << 24);
			num = cmd[8] + (cmd[7] << 8);
		} else {
			block = cmd[3] + (cmd[2] << 8) +
				((cmd[1] & 0x1f) << 16);
			num = cmd[4];
		}
		errsts = resp_write(SCpnt, upper_blk, block, num, devip);
		if (inj_recovered && (0 == errsts)) {
			mk_sense_buffer(devip, RECOVERED_ERROR,
					THRESHHOLD_EXCEEDED, 0);
			errsts = check_condition_result;
		}
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		errsts = resp_mode_sense(SCpnt, target, devip);
		break;
	case SYNCHRONIZE_CACHE:
		errsts = check_is_disk(SCpnt, devip);
		break;
	default:
		if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
			printk(KERN_INFO "scsi_ses: Opcode: 0x%x not "
			       "supported\n", *cmd);
		if ((errsts = check_reset(SCpnt, devip)))
			break;	/* Unit attention takes precedence */
		mk_sense_buffer(devip, ILLEGAL_REQUEST, INVALID_OPCODE, 0);
		errsts = check_condition_result;
		break;
	}
	return schedule_resp(SCpnt, devip, done, errsts, scsi_ses_delay);
}

static int scsi_ses_ioctl(struct scsi_device *dev, int cmd, void __user *arg)
{
	if (SCSI_SES_OPT_NOISE & scsi_ses_opts) {
		printk(KERN_INFO "scsi_ses: ioctl: cmd=0x%x\n", cmd);
	}
	return -EINVAL;
	/* return -ENOTTY; // correct return but upsets fdisk */
}

static int check_reset(struct scsi_cmnd * SCpnt, struct sses_dev_info * devip)
{
	if (devip->reset) {
		if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
			printk(KERN_INFO "scsi_ses: Reporting Unit "
			       "attention: power on reset\n");
		devip->reset = 0;
		mk_sense_buffer(devip, UNIT_ATTENTION, POWERON_RESET, 0);
		return check_condition_result;
	}
	return 0;
}

static int check_is_disk(struct scsi_cmnd * SCpnt,
			 struct sses_dev_info * devip)
{
	int res;

	res = check_reset(SCpnt, devip);
	if (res)
		return res;
	if (scsi_ses_ses_only) {
		if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
			printk(KERN_INFO "scsi_ses: Since not disk, "
			       "illegal opcode\n");
		mk_sense_buffer(devip, ILLEGAL_REQUEST, INVALID_OPCODE, 0);
		return check_condition_result;
	}
	return 0;
}

/* Returns 0 if ok else (DID_ERROR << 16). Sets scp->resid . */
static int fill_from_dev_buffer(struct scsi_cmnd * scp, unsigned char * arr,
				int arr_len)
{
	int k, req_len, act_len, len, active;
	void * kaddr;
	void * kaddr_off;
	struct scatterlist * sgpnt;

	if (0 == scp->request_bufflen)
		return 0;
	if (NULL == scp->request_buffer)
		return (DID_ERROR << 16);
	if (! ((scp->sc_data_direction == DMA_BIDIRECTIONAL) ||
	      (scp->sc_data_direction == DMA_FROM_DEVICE)))
		return (DID_ERROR << 16);
	if (0 == scp->use_sg) {
		req_len = scp->request_bufflen;
		act_len = (req_len < arr_len) ? req_len : arr_len;
		memcpy(scp->request_buffer, arr, act_len);
		scp->resid = req_len - act_len;
		return 0;
	}
	sgpnt = (struct scatterlist *)scp->request_buffer;
	active = 1;
	for (k = 0, req_len = 0, act_len = 0; k < scp->use_sg; ++k, ++sgpnt) {
		if (active) {
			kaddr = (unsigned char *)
				kmap_atomic(sgpnt->page, KM_USER0);
			if (NULL == kaddr)
				return (DID_ERROR << 16);
			kaddr_off = (unsigned char *)kaddr + sgpnt->offset;
			len = sgpnt->length;
			if ((req_len + len) > arr_len) {
				active = 0;
				len = arr_len - req_len;
			}
			memcpy(kaddr_off, arr + req_len, len);
			kunmap_atomic(kaddr, KM_USER0);
			act_len += len;
		}
		req_len += sgpnt->length;
	}
	scp->resid = req_len - act_len;
	return 0;
}

/* Returns number of bytes fetched into 'arr' or -1 if error. */
static int fetch_to_dev_buffer(struct scsi_cmnd * scp, unsigned char * arr,
			       int max_arr_len)
{
	int k, req_len, len, fin;
	void * kaddr;
	void * kaddr_off;
	struct scatterlist * sgpnt;

	if (0 == scp->request_bufflen)
		return 0;
	if (NULL == scp->request_buffer)
		return -1;
	if (! ((scp->sc_data_direction == DMA_BIDIRECTIONAL) ||
	      (scp->sc_data_direction == DMA_TO_DEVICE)))
		return -1;
	if (0 == scp->use_sg) {
		req_len = scp->request_bufflen;
		len = (req_len < max_arr_len) ? req_len : max_arr_len;
		memcpy(arr, scp->request_buffer, len);
		return len;
	}
	sgpnt = (struct scatterlist *)scp->request_buffer;
	for (k = 0, req_len = 0, fin = 0; k < scp->use_sg; ++k, ++sgpnt) {
		kaddr = (unsigned char *)kmap_atomic(sgpnt->page, KM_USER0);
		if (NULL == kaddr)
			return -1;
		kaddr_off = (unsigned char *)kaddr + sgpnt->offset;
		len = sgpnt->length;
		if ((req_len + len) > max_arr_len) {
			len = max_arr_len - req_len;
			fin = 1;
		}
		memcpy(arr + req_len, kaddr_off, len);
		kunmap_atomic(kaddr, KM_USER0);
		if (fin)
			return req_len + len;
		req_len += sgpnt->length;
	}
	return req_len;
}

/*Zacharia Mathew 20041216*/
static const char * inq_logical_id = "1234567"; /*vendor id, product id and product rev shown in inquiry 
										    command shall be shown by the ses device.*/
static const char * inq_vendor_id = "Linux   ";
static const char * inq_product_id = "scsi_ses        ";
static const char * inq_product_rev = "0004";

static int inquiry_evpd_83(unsigned char * arr, int dev_id_num,
			   const char * dev_id_str, int dev_id_str_len)
{
	int num;

	/* Two identification descriptors: */
	/* T10 vendor identifier field format (faked) */
	arr[0] = 0x2;	/* ASCII */
	arr[1] = 0x1;
	arr[2] = 0x0;
	memcpy(&arr[4], inq_vendor_id, 8);
	memcpy(&arr[12], inq_product_id, 16);
	memcpy(&arr[28], dev_id_str, dev_id_str_len);
	num = 8 + 16 + dev_id_str_len;
	arr[3] = num;
	num += 4;
	/* NAA IEEE registered identifier (faked) */
	arr[num] = 0x1;	/* binary */
	arr[num + 1] = 0x3;
	arr[num + 2] = 0x0;
	arr[num + 3] = 0x8;
	arr[num + 4] = 0x51;	/* ieee company id=0x123456 (faked) */
	arr[num + 5] = 0x23;
	arr[num + 6] = 0x45;
	arr[num + 7] = 0x60;
	arr[num + 8] = (dev_id_num >> 24);
	arr[num + 9] = (dev_id_num >> 16) & 0xff;
	arr[num + 10] = (dev_id_num >> 8) & 0xff;
	arr[num + 11] = dev_id_num & 0xff;
	return num + 12;
}


#define SSES_LONG_INQ_SZ 96
#define SSES_MAX_INQ_ARR_SZ 128

static int resp_inquiry(struct scsi_cmnd * scp, int target,
			struct sses_dev_info * devip)
{
	unsigned char pq_pdt;
	unsigned char arr[SSES_MAX_INQ_ARR_SZ];
	unsigned char *cmd = (unsigned char *)scp->cmnd;
	int alloc_len;

	alloc_len = (cmd[3] << 8) + cmd[4];
	memset(arr, 0, SSES_MAX_INQ_ARR_SZ);
	pq_pdt = scsi_ses_ses_only ? 0xd /* SES */ : 0x0;
	arr[0] = pq_pdt;
	if (0x2 & cmd[1]) {  /* CMDDT bit set */
		mk_sense_buffer(devip, ILLEGAL_REQUEST, INVALID_FIELD_IN_CDB,
			       	0);
		return check_condition_result;
	} else if (0x1 & cmd[1]) {  /* EVPD bit set */
		int dev_id_num, len;
		char dev_id_str[6];
		
		dev_id_num = ((devip->sdbg_host->shost->host_no + 1) * 2000) +
			     (devip->target * 1000) + devip->lun;
		len = scnprintf(dev_id_str, 6, "%d", dev_id_num);
		if (0 == cmd[2]) { /* supported vital product data pages */
			arr[3] = 3;
			arr[4] = 0x0; /* this page */
			arr[5] = 0x80; /* unit serial number */
			arr[6] = 0x83; /* device identification */
		} else if (0x80 == cmd[2]) { /* unit serial number */
			arr[1] = 0x80;
			arr[3] = len;
			memcpy(&arr[4], dev_id_str, len);
		} else if (0x83 == cmd[2]) { /* device identification */
			arr[1] = 0x83;
			arr[3] = inquiry_evpd_83(&arr[4], dev_id_num,
						 dev_id_str, len);
		} else {
			/* Illegal request, invalid field in cdb */
			mk_sense_buffer(devip, ILLEGAL_REQUEST,
					INVALID_FIELD_IN_CDB, 0);
			return check_condition_result;
		}
		return fill_from_dev_buffer(scp, arr,
			    min(alloc_len, SSES_MAX_INQ_ARR_SZ));
	}
	/* drops through here for a standard inquiry */
	arr[1] = DEV_REMOVEABLE(target) ? 0x80 : 0;	/* Removable disk */
	arr[2] = scsi_ses_scsi_level;
	arr[3] = 2;    /* response_data_format==2 */
	arr[4] = SSES_LONG_INQ_SZ - 5;
	arr[6] = 0x1; /* claim: ADDR16 */
	arr[6] |= 0x40; 	/* ... claim: EncServ (enclosure services) */
	arr[7] = 0x3a; /* claim: WBUS16, SYNC, LINKED + CMDQUE */
	memcpy(&arr[8], inq_vendor_id, 8);
	memcpy(&arr[16], inq_product_id, 16);
	memcpy(&arr[32], inq_product_rev, 4);
	/* version descriptors (2 bytes each) follow */
	arr[58] = 0x0; arr[59] = 0x40; /* SAM-2 */
	arr[60] = 0x3; arr[61] = 0x0;  /* SPC-3 */
	arr[62] = 0x3; arr[63] = 0xE0; /* SES-2 */
	if (scsi_ses_ses_only == 0) {
		arr[64] = 0x1; arr[65] = 0x80; /* SBC */
	}
	return fill_from_dev_buffer(scp, arr,
			    min(alloc_len, SSES_LONG_INQ_SZ));
}

static int resp_requests(struct scsi_cmnd * scp,
			 struct sses_dev_info * devip)
{
	unsigned char * sbuff;
	unsigned char *cmd = (unsigned char *)scp->cmnd;
	unsigned char arr[SSES_SENSE_LEN];
	int len = 18;

	memset(arr, 0, SSES_SENSE_LEN);
	if (devip->reset == 1)
		mk_sense_buffer(devip, 0, NO_ADDED_SENSE, 0);
	sbuff = devip->sense_buff;
	if ((cmd[1] & 1) && (! scsi_ses_dsense)) {
		/* DESC bit set and sense_buff in fixed format */
		arr[0] = 0x72;
		arr[1] = sbuff[2];     /* sense key */
		arr[2] = sbuff[12];    /* asc */
		arr[3] = sbuff[13];    /* ascq */
		len = 8;
	} else
		memcpy(arr, sbuff, SSES_SENSE_LEN);
	mk_sense_buffer(devip, 0, NO_ADDED_SENSE, 0);
	return fill_from_dev_buffer(scp, arr, len);
}

#define SSES_READCAP_ARR_SZ 8
static int resp_readcap(struct scsi_cmnd * scp,
			struct sses_dev_info * devip)
{
	unsigned char arr[SSES_READCAP_ARR_SZ];
	unsigned long capac;
	int errsts;

	if ((errsts = check_is_disk(scp, devip)))
		return errsts;
	memset(arr, 0, SSES_READCAP_ARR_SZ);
	capac = (unsigned long)sses_capacity - 1;
	arr[0] = (capac >> 24);
	arr[1] = (capac >> 16) & 0xff;
	arr[2] = (capac >> 8) & 0xff;
	arr[3] = capac & 0xff;
	arr[6] = (SECT_SIZE_PER(target) >> 8) & 0xff;
	arr[7] = SECT_SIZE_PER(target) & 0xff;
	return fill_from_dev_buffer(scp, arr, SSES_READCAP_ARR_SZ);
}

/* <<Following mode page info copied from ST318451LW>> */

static int resp_err_recov_pg(unsigned char * p, int pcontrol, int target)
{	/* Read-Write Error Recovery page for mode_sense */
	unsigned char err_recov_pg[] = {0x1, 0xa, 0xc0, 11, 240, 0, 0, 0,
					5, 0, 0xff, 0xff};

	memcpy(p, err_recov_pg, sizeof(err_recov_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(err_recov_pg) - 2);
	return sizeof(err_recov_pg);
}

static int resp_disconnect_pg(unsigned char * p, int pcontrol, int target)
{ 	/* Disconnect-Reconnect page for mode_sense */
	unsigned char disconnect_pg[] = {0x2, 0xe, 128, 128, 0, 10, 0, 0,
					 0, 0, 0, 0, 0, 0, 0, 0};

	memcpy(p, disconnect_pg, sizeof(disconnect_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(disconnect_pg) - 2);
	return sizeof(disconnect_pg);
}

static int resp_format_pg(unsigned char * p, int pcontrol, int target)
{       /* Format device page for mode_sense */
        unsigned char format_pg[] = {0x3, 0x16, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0x40, 0, 0, 0};

        memcpy(p, format_pg, sizeof(format_pg));
        p[10] = (sses_sectors_per >> 8) & 0xff;
        p[11] = sses_sectors_per & 0xff;
        p[12] = (SECT_SIZE >> 8) & 0xff;
        p[13] = SECT_SIZE & 0xff;
        if (DEV_REMOVEABLE(target))
                p[20] |= 0x20; /* should agree with INQUIRY */
        if (1 == pcontrol)
                memset(p + 2, 0, sizeof(format_pg) - 2);
        return sizeof(format_pg);
}

static int resp_caching_pg(unsigned char * p, int pcontrol, int target)
{ 	/* Caching page for mode_sense */
	unsigned char caching_pg[] = {0x8, 18, 0x14, 0, 0xff, 0xff, 0, 0,
		0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0, 0,     0, 0, 0, 0};

	memcpy(p, caching_pg, sizeof(caching_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(caching_pg) - 2);
	return sizeof(caching_pg);
}

static int resp_ctrl_m_pg(unsigned char * p, int pcontrol, int target)
{ 	/* Control mode page for mode_sense */
	unsigned char ctrl_m_pg[] = {0xa, 10, 2, 0, 0, 0, 0, 0,
				     0, 0, 0x2, 0x4b};

	if (scsi_ses_dsense)
		ctrl_m_pg[2] |= 0x4;
	memcpy(p, ctrl_m_pg, sizeof(ctrl_m_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(ctrl_m_pg) - 2);
	return sizeof(ctrl_m_pg);
}

static int resp_iec_m_pg(unsigned char * p, int pcontrol, int target)
{	/* Informational Exceptions control mode page for mode_sense */
	unsigned char iec_m_pg[] = {0x1c, 0xa, 0x08, 0, 0, 0, 0, 0,
				    0, 0, 0x0, 0x0};
	memcpy(p, iec_m_pg, sizeof(iec_m_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(iec_m_pg) - 2);
	return sizeof(iec_m_pg);
}

#define SSES_MAX_MSENSE_SZ 256

static int resp_mode_sense(struct scsi_cmnd * scp, int target,
			   struct sses_dev_info * devip)
{
	unsigned char dbd;
	int pcontrol, pcode, subpcode;
	unsigned char dev_spec;
	int alloc_len, msense_6, offset, len, errsts;
	unsigned char * ap;
	unsigned char arr[SSES_MAX_MSENSE_SZ];
	unsigned char *cmd = (unsigned char *)scp->cmnd;

	if ((errsts = check_reset(scp, devip)))
		return errsts;
	dbd = cmd[1] & 0x8;
	pcontrol = (cmd[2] & 0xc0) >> 6;
	pcode = cmd[2] & 0x3f;
	subpcode = cmd[3];
	msense_6 = (MODE_SENSE == cmd[0]);
	alloc_len = msense_6 ? cmd[4] : ((cmd[7] << 8) | cmd[8]);
	memset(arr, 0, SSES_MAX_MSENSE_SZ);
	if (0x3 == pcontrol) {  /* Saving values not supported */
		mk_sense_buffer(devip, ILLEGAL_REQUEST, SAVING_PARAMS_UNSUP,
			       	0);
		return check_condition_result;
	}
	dev_spec = DEV_READONLY(target) ? 0x80 : 0x0;
	if (msense_6) {
		arr[2] = dev_spec;
		offset = 4;
	} else {
		arr[3] = dev_spec;
		offset = 8;
	}
	ap = arr + offset;

	if (0 != subpcode) { /* TODO: Control Extension page */
		mk_sense_buffer(devip, ILLEGAL_REQUEST, INVALID_FIELD_IN_CDB,
			       	0);
		return check_condition_result;
	}
	switch (pcode) {
	case 0x1:	/* Read-Write error recovery page, direct access */
		len = resp_err_recov_pg(ap, pcontrol, target);
		offset += len;
		break;
	case 0x2:	/* Disconnect-Reconnect page, all devices */
		len = resp_disconnect_pg(ap, pcontrol, target);
		offset += len;
		break;
        case 0x3:       /* Format device page, direct access */
                len = resp_format_pg(ap, pcontrol, target);
                offset += len;
                break;
	case 0x8:	/* Caching page, direct access */
		len = resp_caching_pg(ap, pcontrol, target);
		offset += len;
		break;
	case 0xa:	/* Control Mode page, all devices */
		len = resp_ctrl_m_pg(ap, pcontrol, target);
		offset += len;
		break;
	case 0x1c:	/* Informational Exceptions Mode page, all devices */
		len = resp_iec_m_pg(ap, pcontrol, target);
		offset += len;
		break;
	case 0x3f:	/* Read all Mode pages */
		len = resp_err_recov_pg(ap, pcontrol, target);
		len += resp_disconnect_pg(ap + len, pcontrol, target);
		len += resp_format_pg(ap + len, pcontrol, target);
		len += resp_caching_pg(ap + len, pcontrol, target);
		len += resp_ctrl_m_pg(ap + len, pcontrol, target);
		len += resp_iec_m_pg(ap + len, pcontrol, target);
		offset += len;
		break;
	default:
		mk_sense_buffer(devip, ILLEGAL_REQUEST, INVALID_FIELD_IN_CDB,
			       	0);
		return check_condition_result;
	}
	if (msense_6)
		arr[0] = offset - 1;
	else {
		arr[0] = ((offset - 2) >> 8) & 0xff;
		arr[1] = (offset - 2) & 0xff;
	}
	return fill_from_dev_buffer(scp, arr, min(alloc_len, offset));
}

static int resp_read(struct scsi_cmnd * SCpnt, int upper_blk, int block,
		     int num, struct sses_dev_info * devip)
{
	unsigned long iflags;
	int ret;

	if (upper_blk || (block + num > sses_capacity)) {
		mk_sense_buffer(devip, ILLEGAL_REQUEST, ADDR_OUT_OF_RANGE,
				0);
		return check_condition_result;
	}
	read_lock_irqsave(&atomic_rw, iflags);
	ret = fill_from_dev_buffer(SCpnt, fake_storep + (block * SECT_SIZE),
			   	   num * SECT_SIZE);
	read_unlock_irqrestore(&atomic_rw, iflags);
	return ret;
}

static int resp_write(struct scsi_cmnd * SCpnt, int upper_blk, int block,
		      int num, struct sses_dev_info * devip)
{
	unsigned long iflags;
	int res;

	if (upper_blk || (block + num > sses_capacity)) {
		mk_sense_buffer(devip, ILLEGAL_REQUEST, ADDR_OUT_OF_RANGE,
			       	0);
		return check_condition_result;
	}

	write_lock_irqsave(&atomic_rw, iflags);
	res = fetch_to_dev_buffer(SCpnt, fake_storep + (block * SECT_SIZE),
			   	  num * SECT_SIZE);
	write_unlock_irqrestore(&atomic_rw, iflags);
	if (-1 == res)
		return (DID_ERROR << 16);
	else if ((res < (num * SECT_SIZE)) &&
		 (SCSI_SES_OPT_NOISE & scsi_ses_opts))
		printk(KERN_INFO "scsi_ses: write: cdb indicated=%d, "
		       " IO sent=%d bytes\n", num * SECT_SIZE, res);
	return 0;
}

#define SSES_RLUN_ARR_SZ 128

static int resp_report_luns(struct scsi_cmnd * scp,
			    struct sses_dev_info * devip)
{
	unsigned int alloc_len;
	int lun_cnt, i, upper;
	unsigned char *cmd = (unsigned char *)scp->cmnd;
	int select_report = (int)cmd[2];
	struct scsi_lun *one_lun;
	unsigned char arr[SSES_RLUN_ARR_SZ];

	alloc_len = cmd[9] + (cmd[8] << 8) + (cmd[7] << 16) + (cmd[6] << 24);
	if ((alloc_len < 16) || (select_report > 2)) {
		mk_sense_buffer(devip, ILLEGAL_REQUEST, INVALID_FIELD_IN_CDB,
			       	0);
		return check_condition_result;
	}
	/* can produce response with up to 16k luns (lun 0 to lun 16383) */
	memset(arr, 0, SSES_RLUN_ARR_SZ);
	lun_cnt = scsi_ses_max_luns;
	arr[2] = ((sizeof(struct scsi_lun) * lun_cnt) >> 8) & 0xff;
	arr[3] = (sizeof(struct scsi_lun) * lun_cnt) & 0xff;
	lun_cnt = min((int)((SSES_RLUN_ARR_SZ - 8) /
			    sizeof(struct scsi_lun)), lun_cnt);
	one_lun = (struct scsi_lun *) &arr[8];
	for (i = 0; i < lun_cnt; i++) {
		upper = (i >> 8) & 0x3f;
		if (upper)
			one_lun[i].scsi_lun[0] =
			    (upper | (SAM2_LUN_ADDRESS_METHOD << 6));
		one_lun[i].scsi_lun[1] = i & 0xff;
	}
	return fill_from_dev_buffer(scp, arr,
				    min((int)alloc_len, SSES_RLUN_ARR_SZ));
}

/* When timer goes off this function is called. */
static void timer_intr_handler(unsigned long indx)
{
	struct sses_queued_cmd * sqcp;
	unsigned long iflags;

	if (indx >= SCSI_SES_CANQUEUE) {
		printk(KERN_ERR "scsi_ses:timer_intr_handler: indx too "
		       "large\n");
		return;
	}
	spin_lock_irqsave(&queued_arr_lock, iflags);
	sqcp = &queued_arr[(int)indx];
	if (! sqcp->in_use) {
		printk(KERN_ERR "scsi_ses:timer_intr_handler: Unexpected "
		       "interrupt\n");
		spin_unlock_irqrestore(&queued_arr_lock, iflags);
		return;
	}
	sqcp->in_use = 0;
	if (sqcp->done_funct) {
		sqcp->a_cmnd->result = sqcp->scsi_result;
		sqcp->done_funct(sqcp->a_cmnd); /* callback to mid level */
	}
	sqcp->done_funct = NULL;
	spin_unlock_irqrestore(&queued_arr_lock, iflags);
}

static int scsi_ses_slave_alloc(struct scsi_device * sdp)
{
	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: slave_alloc <%u %u %u %u>\n",
		       sdp->host->host_no, sdp->channel, sdp->id, sdp->lun);
	return 0;
}

static int scsi_ses_slave_configure(struct scsi_device * sdp)
{
	struct sses_dev_info * devip;

	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: slave_configure <%u %u %u %u>\n",
		       sdp->host->host_no, sdp->channel, sdp->id, sdp->lun);
	if (sdp->host->max_cmd_len != SCSI_SES_MAX_CMD_LEN)
		sdp->host->max_cmd_len = SCSI_SES_MAX_CMD_LEN;
	devip = devInfoReg(sdp);
	sdp->hostdata = devip;
	if (sdp->host->cmd_per_lun)
		scsi_adjust_queue_depth(sdp, SSES_TAGGED_QUEUING,
					sdp->host->cmd_per_lun);
	return 0;
}

static void scsi_ses_slave_destroy(struct scsi_device * sdp)
{
	struct sses_dev_info * devip =
				(struct sses_dev_info *)sdp->hostdata;

	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: slave_destroy <%u %u %u %u>\n",
		       sdp->host->host_no, sdp->channel, sdp->id, sdp->lun);
	if (devip) {
		/* make this slot avaliable for re-use */
		devip->used = 0;
		sdp->hostdata = NULL;
	}
}

static struct sses_dev_info * devInfoReg(struct scsi_device * sdev)
{
	struct sses_host_info * sdbg_host;
	struct sses_dev_info * open_devip = NULL;
	struct sses_dev_info * devip =
			(struct sses_dev_info *)sdev->hostdata;

	if (devip)
		return devip;
	sdbg_host = *(struct sses_host_info **) sdev->host->hostdata;
        if(! sdbg_host) {
                printk(KERN_ERR "Host info NULL\n");
		return NULL;
        }
	list_for_each_entry(devip, &sdbg_host->dev_info_list, dev_list) {
		if ((devip->used) && (devip->channel == sdev->channel) &&
                    (devip->target == sdev->id) &&
                    (devip->lun == sdev->lun))
                        return devip;
		else {
			if ((!devip->used) && (!open_devip))
				open_devip = devip;
		}
	}
	if (NULL == open_devip) { /* try and make a new one */
		open_devip = kmalloc(sizeof(*open_devip),GFP_KERNEL);
		if (NULL == open_devip) {
			printk(KERN_ERR "%s: out of memory at line %d\n",
				__FUNCTION__, __LINE__);
			return NULL;
		}
		memset(open_devip, 0, sizeof(*open_devip));
		open_devip->sdbg_host = sdbg_host;
		list_add_tail(&open_devip->dev_list,
		&sdbg_host->dev_info_list);
	}
        if (open_devip) {
		open_devip->channel = sdev->channel;
		open_devip->target = sdev->id;
		open_devip->lun = sdev->lun;
		open_devip->sdbg_host = sdbg_host;
		open_devip->reset = 1;
		open_devip->used = 1;
		memset(open_devip->sense_buff, 0, SSES_SENSE_LEN);
		if (scsi_ses_dsense)
			open_devip->sense_buff[0] = 0x72;
		else {
			open_devip->sense_buff[0] = 0x70;
			open_devip->sense_buff[7] = 0xa;
		}
		return open_devip;
        }
        return NULL;
}

static void mk_sense_buffer(struct sses_dev_info * devip, int key,
			    int asc, int asq)
{
	unsigned char * sbuff;

	sbuff = devip->sense_buff;
	memset(sbuff, 0, SSES_SENSE_LEN);
	if (scsi_ses_dsense) {
		sbuff[0] = 0x72;  /* descriptor, current */
		sbuff[1] = key;
		sbuff[2] = asc;
		sbuff[3] = asq;
	} else {
		sbuff[0] = 0x70;  /* fixed, current */
		sbuff[2] = key;
		sbuff[7] = 0xa;	  /* implies 18 byte sense buffer */
		sbuff[12] = asc;
		sbuff[13] = asq;
	}
	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses:    [sense_key,asc,ascq]: "
		      "[0x%x,0x%x,0x%x]\n", key, asc, asq);
}

static int scsi_ses_abort(struct scsi_cmnd * SCpnt)
{
	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: abort\n");
	++num_aborts;
	stop_queued_cmnd(SCpnt);
	return SUCCESS;
}

static int scsi_ses_biosparam(struct scsi_device *sdev,
		struct block_device * bdev, sector_t capacity, int *info)
{
	int res;
	unsigned char *buf;

	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: biosparam\n");
	buf = scsi_bios_ptable(bdev);
	if (buf) {
		res = scsi_partsize(buf, capacity,
				    &info[2], &info[0], &info[1]);
		kfree(buf);
		if (! res)
			return res;
	}
	info[0] = sses_heads;
	info[1] = sses_sectors_per;
	info[2] = sses_cylinders_per;
	return 0;
}

static int scsi_ses_device_reset(struct scsi_cmnd * SCpnt)
{
	struct sses_dev_info * devip;

	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: device_reset\n");
	++num_dev_resets;
	if (SCpnt) {
		devip = devInfoReg(SCpnt->device);
		if (devip)
			devip->reset = 1;
	}
	return SUCCESS;
}

static int scsi_ses_bus_reset(struct scsi_cmnd * SCpnt)
{
	struct sses_host_info *sdbg_host;
        struct sses_dev_info * dev_info;
        struct scsi_device * sdp;
        struct Scsi_Host * hp;

	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: bus_reset\n");
	++num_bus_resets;
	if (SCpnt && ((sdp = SCpnt->device)) && ((hp = sdp->host))) {
		sdbg_host = *(struct sses_host_info **) hp->hostdata;
		if (sdbg_host) {
			list_for_each_entry(dev_info,
                                            &sdbg_host->dev_info_list,
                                            dev_list)
				dev_info->reset = 1;
		}
	}
	return SUCCESS;
}

static int scsi_ses_host_reset(struct scsi_cmnd * SCpnt)
{
	struct sses_host_info * sdbg_host;
        struct sses_dev_info * dev_info;

	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: host_reset\n");
	++num_host_resets;
        spin_lock(&sses_host_list_lock);
        list_for_each_entry(sdbg_host, &sses_host_list, host_list) {
                list_for_each_entry(dev_info, &sdbg_host->dev_info_list,
                                    dev_list)
                        dev_info->reset = 1;
        }
        spin_unlock(&sses_host_list_lock);
	stop_all_queued();
	return SUCCESS;
}

/* Returns 1 if found 'cmnd' and deleted its timer. else returns 0 */
static int stop_queued_cmnd(struct scsi_cmnd * cmnd)
{
	unsigned long iflags;
	int k;
	struct sses_queued_cmd * sqcp;

	spin_lock_irqsave(&queued_arr_lock, iflags);
	for (k = 0; k < SCSI_SES_CANQUEUE; ++k) {
		sqcp = &queued_arr[k];
		if (sqcp->in_use && (cmnd == sqcp->a_cmnd)) {
			del_timer_sync(&sqcp->cmnd_timer);
			sqcp->in_use = 0;
			sqcp->a_cmnd = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&queued_arr_lock, iflags);
	return (k < SCSI_SES_CANQUEUE) ? 1 : 0;
}

/* Deletes (stops) timers of all queued commands */
static void stop_all_queued(void)
{
	unsigned long iflags;
	int k;
	struct sses_queued_cmd * sqcp;

	spin_lock_irqsave(&queued_arr_lock, iflags);
	for (k = 0; k < SCSI_SES_CANQUEUE; ++k) {
		sqcp = &queued_arr[k];
		if (sqcp->in_use && sqcp->a_cmnd) {
			del_timer_sync(&sqcp->cmnd_timer);
			sqcp->in_use = 0;
			sqcp->a_cmnd = NULL;
		}
	}
	spin_unlock_irqrestore(&queued_arr_lock, iflags);
}

/* Initializes timers in queued array */
static void __init init_all_queued(void)
{
	unsigned long iflags;
	int k;
	struct sses_queued_cmd * sqcp;

	spin_lock_irqsave(&queued_arr_lock, iflags);
	for (k = 0; k < SCSI_SES_CANQUEUE; ++k) {
		sqcp = &queued_arr[k];
		init_timer(&sqcp->cmnd_timer);
		sqcp->in_use = 0;
		sqcp->a_cmnd = NULL;
	}
	spin_unlock_irqrestore(&queued_arr_lock, iflags);
}

static void __init sses_build_parts(unsigned char * ramp)
{
	struct partition * pp;
	int starts[SSES_MAX_PARTS + 2];
	int sectors_per_part, num_sectors, k;
	int heads_by_sects, start_sec, end_sec;

	/* assume partition table already zeroed */
	if ((scsi_ses_num_parts < 1) || (sses_store_size < 1048576))
		return;
	if (scsi_ses_num_parts > SSES_MAX_PARTS) {
		scsi_ses_num_parts = SSES_MAX_PARTS;
		printk(KERN_WARNING "scsi_ses:build_parts: reducing "
				    "partitions to %d\n", SSES_MAX_PARTS);
	}
	num_sectors = (int)(sses_store_size / SECT_SIZE);
	sectors_per_part = (num_sectors - sses_sectors_per)
			   / scsi_ses_num_parts;
	heads_by_sects = sses_heads * sses_sectors_per;
        starts[0] = sses_sectors_per;
	for (k = 1; k < scsi_ses_num_parts; ++k)
		starts[k] = ((k * sectors_per_part) / heads_by_sects)
			    * heads_by_sects;
	starts[scsi_ses_num_parts] = num_sectors;
	starts[scsi_ses_num_parts + 1] = 0;

	ramp[510] = 0x55;	/* magic partition markings */
	ramp[511] = 0xAA;
	pp = (struct partition *)(ramp + 0x1be);
	for (k = 0; starts[k + 1]; ++k, ++pp) {
		start_sec = starts[k];
		end_sec = starts[k + 1] - 1;
		pp->boot_ind = 0;

		pp->cyl = start_sec / heads_by_sects;
		pp->head = (start_sec - (pp->cyl * heads_by_sects))
			   / sses_sectors_per;
		pp->sector = (start_sec % sses_sectors_per) + 1;

		pp->end_cyl = end_sec / heads_by_sects;
		pp->end_head = (end_sec - (pp->end_cyl * heads_by_sects))
			       / sses_sectors_per;
		pp->end_sector = (end_sec % sses_sectors_per) + 1;

		pp->start_sect = start_sec;
		pp->nr_sects = end_sec - start_sec + 1;
		pp->sys_ind = 0x83;	/* plain Linux partition */
	}
}

static int schedule_resp(struct scsi_cmnd * cmnd,
			 struct sses_dev_info * devip,
			 done_funct_t done, int scsi_result, int delta_jiff)
{
	if ((SCSI_SES_OPT_NOISE & scsi_ses_opts) && cmnd) {
		if (scsi_result) {
			struct scsi_device * sdp = cmnd->device;

			printk(KERN_INFO "scsi_ses:    <%u %u %u %u> "
			       "non-zero result=0x%x\n", sdp->host->host_no,
			       sdp->channel, sdp->id, sdp->lun, scsi_result);
		}
	}
	if (cmnd && devip) {
		/* simulate autosense by this driver */
		if (SAM_STAT_CHECK_CONDITION == (scsi_result & 0xff))
			memcpy(cmnd->sense_buffer, devip->sense_buff,
			       (SCSI_SENSE_BUFFERSIZE > SSES_SENSE_LEN) ?
			       SSES_SENSE_LEN : SCSI_SENSE_BUFFERSIZE);
	}
	if (delta_jiff <= 0) {
		if (cmnd)
			cmnd->result = scsi_result;
		if (done)
			done(cmnd);
		return 0;
	} else {
		unsigned long iflags;
		int k;
		struct sses_queued_cmd * sqcp = NULL;

		spin_lock_irqsave(&queued_arr_lock, iflags);
		for (k = 0; k < SCSI_SES_CANQUEUE; ++k) {
			sqcp = &queued_arr[k];
			if (! sqcp->in_use)
				break;
		}
		if (k >= SCSI_SES_CANQUEUE) {
			spin_unlock_irqrestore(&queued_arr_lock, iflags);
			printk(KERN_WARNING "scsi_ses: can_queue exceeded\n");
			return 1;	/* report busy to mid level */
		}
		sqcp->in_use = 1;
		sqcp->a_cmnd = cmnd;
		sqcp->scsi_result = scsi_result;
		sqcp->done_funct = done;
		sqcp->cmnd_timer.function = timer_intr_handler;
		sqcp->cmnd_timer.data = k;
		sqcp->cmnd_timer.expires = jiffies + delta_jiff;
		add_timer(&sqcp->cmnd_timer);
		spin_unlock_irqrestore(&queued_arr_lock, iflags);
		if (cmnd)
			cmnd->result = 0;
		return 0;
	}
}

/* Set 'perm' (4th argument) to 0 to disable module_param's definition
 * of sysfs parameters (which module_param doesn't yet support).
 * Sysfs parameters defined explicitly below.
 */
module_param_named(delay, scsi_ses_delay, int, S_IRUGO | S_IWUSR);
module_param_named(dev_size_mb, scsi_ses_dev_size_mb, int, S_IRUGO);
module_param_named(dsense, scsi_ses_dsense, int, S_IRUGO | S_IWUSR);
module_param_named(every_nth, scsi_ses_every_nth, int, S_IRUGO | S_IWUSR);
module_param_named(num_parts, scsi_ses_num_parts, int, S_IRUGO);
module_param_named(opts, scsi_ses_opts, int, S_IRUGO | S_IWUSR);
module_param_named(scsi_level, scsi_ses_scsi_level, int, S_IRUGO);
module_param_named(ses_only, scsi_ses_ses_only, int, S_IRUGO | S_IWUSR);

MODULE_AUTHOR("Douglas Gilbert and Zacharia Mathew");
MODULE_DESCRIPTION("SCSI dummy SES target driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(SCSI_SES_VERSION);

MODULE_PARM_DESC(delay, "# of jiffies to delay response(def=1)");
MODULE_PARM_DESC(dev_size_mb, "size in MB of ram disk (def=8)");
MODULE_PARM_DESC(dsense, "use descriptor sense format(def=0[fixed])");
MODULE_PARM_DESC(every_nth, "timeout every nth command(def=0)");
MODULE_PARM_DESC(num_parts, "number of partitions(def=0)");
MODULE_PARM_DESC(opts, "1->noisy (def=0)");
MODULE_PARM_DESC(scsi_level, "SCSI level to simulate(def=5[SPC-3])");
MODULE_PARM_DESC(ses_only, "1->enclosure only, 0(def)->disk+enclosure");


static char sses_info[256];

static const char * scsi_ses_info(struct Scsi_Host * shp)
{
	sprintf(sses_info, "scsi_ses, version %s [%s], "
		"dev_size_mb=%d, opts=0x%x", SCSI_SES_VERSION,
		scsi_ses_version_date, scsi_ses_dev_size_mb,
		scsi_ses_opts);
	return sses_info;
}

static ssize_t sses_delay_show(struct device_driver * ddp, char * buf)
{
        return scnprintf(buf, PAGE_SIZE, "%d\n", scsi_ses_delay);
}

static ssize_t sses_delay_store(struct device_driver * ddp,
				  const char * buf, size_t count)
{
        int delay;
	char work[20];

        if (1 == sscanf(buf, "%10s", work)) {
		if ((1 == sscanf(work, "%d", &delay)) && (delay >= 0)) {
			scsi_ses_delay = delay;
			return count;
		}
	}
	return -EINVAL;
}
DRIVER_ATTR(delay, S_IRUGO | S_IWUSR, sses_delay_show,
	    sses_delay_store);

static ssize_t sses_every_nth_show(struct device_driver * ddp, char * buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", scsi_ses_every_nth);
}
static ssize_t sses_every_nth_store(struct device_driver * ddp,
                                      const char * buf, size_t count)
{
	int nth;

	if ((count > 0) && (1 == sscanf(buf, "%d", &nth))) {
		scsi_ses_every_nth = nth;
		return count;
	}
	return -EINVAL;
}
DRIVER_ATTR(every_nth, S_IRUGO | S_IWUSR, sses_every_nth_show,
	    sses_every_nth_store);

static ssize_t sses_opts_show(struct device_driver * ddp, char * buf)
{
        return scnprintf(buf, PAGE_SIZE, "0x%x\n", scsi_ses_opts);
}

static ssize_t sses_opts_store(struct device_driver * ddp,
				 const char * buf, size_t count)
{
        int opts;
	char work[20];

        if (1 == sscanf(buf, "%10s", work)) {
		if (0 == strnicmp(work,"0x", 2)) {
			if (1 == sscanf(&work[2], "%x", &opts))
				goto opts_done;
		} else {
			if (1 == sscanf(work, "%d", &opts))
				goto opts_done;
		}
	}
	return -EINVAL;
opts_done:
	scsi_ses_opts = opts;
	return count;
}
DRIVER_ATTR(opts, S_IRUGO | S_IWUSR, sses_opts_show,
	    sses_opts_store);

static ssize_t sses_ses_only_show(struct device_driver * ddp, char * buf)
{
        return scnprintf(buf, PAGE_SIZE, "%d\n", scsi_ses_ses_only);
}
static ssize_t sses_ses_only_store(struct device_driver * ddp,
				   const char * buf, size_t count)
{
        int n;

	if ((count > 0) && (1 == sscanf(buf, "%d", &n)) && (n >= 0)) {
		scsi_ses_ses_only = n;
		return count;
	}
	return -EINVAL;
}
DRIVER_ATTR(ses_only, S_IRUGO | S_IWUSR, sses_ses_only_show,
	    sses_ses_only_store);

static ssize_t sses_dsense_show(struct device_driver * ddp, char * buf)
{
        return scnprintf(buf, PAGE_SIZE, "%d\n", scsi_ses_dsense);
}
static ssize_t sses_dsense_store(struct device_driver * ddp,
				  const char * buf, size_t count)
{
        int n;

	if ((count > 0) && (1 == sscanf(buf, "%d", &n)) && (n >= 0)) {
		scsi_ses_dsense = n;
		return count;
	}
	return -EINVAL;
}
DRIVER_ATTR(dsense, S_IRUGO | S_IWUSR, sses_dsense_show,
	    sses_dsense_store);

static ssize_t sses_dev_size_mb_show(struct device_driver * ddp, char * buf)
{
        return scnprintf(buf, PAGE_SIZE, "%d\n", scsi_ses_dev_size_mb);
}
DRIVER_ATTR(dev_size_mb, S_IRUGO, sses_dev_size_mb_show, NULL);

static ssize_t sses_num_parts_show(struct device_driver * ddp, char * buf)
{
        return scnprintf(buf, PAGE_SIZE, "%d\n", scsi_ses_num_parts);
}
DRIVER_ATTR(num_parts, S_IRUGO, sses_num_parts_show, NULL);

static ssize_t sses_scsi_level_show(struct device_driver * ddp, char * buf)
{
        return scnprintf(buf, PAGE_SIZE, "%d\n", scsi_ses_scsi_level);
}
DRIVER_ATTR(scsi_level, S_IRUGO, sses_scsi_level_show, NULL);

static void do_create_driverfs_files(void)
{
	driver_create_file(&sses_driverfs_driver, &driver_attr_delay);
	driver_create_file(&sses_driverfs_driver, &driver_attr_dev_size_mb);
	driver_create_file(&sses_driverfs_driver, &driver_attr_dsense);
	driver_create_file(&sses_driverfs_driver, &driver_attr_num_parts);
	driver_create_file(&sses_driverfs_driver, &driver_attr_every_nth);
	driver_create_file(&sses_driverfs_driver, &driver_attr_opts);
	driver_create_file(&sses_driverfs_driver, &driver_attr_scsi_level);
	driver_create_file(&sses_driverfs_driver, &driver_attr_ses_only);
}

static void do_remove_driverfs_files(void)
{
	driver_remove_file(&sses_driverfs_driver, &driver_attr_ses_only);
	driver_remove_file(&sses_driverfs_driver, &driver_attr_scsi_level);
	driver_remove_file(&sses_driverfs_driver, &driver_attr_opts);
	driver_remove_file(&sses_driverfs_driver, &driver_attr_num_parts);
	driver_remove_file(&sses_driverfs_driver, &driver_attr_every_nth);
	driver_remove_file(&sses_driverfs_driver, &driver_attr_dsense);
	driver_remove_file(&sses_driverfs_driver, &driver_attr_dev_size_mb);
	driver_remove_file(&sses_driverfs_driver, &driver_attr_delay);
}

static int __init scsi_ses_init(void)
{
	unsigned long sz;
	int host_to_add;
	int k;

	if (scsi_ses_dev_size_mb < 1)
		scsi_ses_dev_size_mb = 1;  /* force minimum 1 MB ramdisk */
	sses_store_size = (unsigned long)scsi_ses_dev_size_mb * 1048576;
	sses_capacity = sses_store_size / SECT_SIZE;

	/* play around with geometry, don't waste too much on track 0 */
	sses_heads = 8;
	sses_sectors_per = 32;
	if (scsi_ses_dev_size_mb >= 16)
		sses_heads = 32;
	else if (scsi_ses_dev_size_mb >= 256)
		sses_heads = 64;
	sses_cylinders_per = (unsigned long)sses_capacity /
			       (sses_sectors_per * sses_heads);
	if (sses_cylinders_per >= 1024) {
		/* other LLDs do this; implies >= 1GB ram disk ... */
		sses_heads = 255;
		sses_sectors_per = 63;
		sses_cylinders_per = (unsigned long)sses_capacity /
			       (sses_sectors_per * sses_heads);
	}

	sz = sses_store_size;
	fake_storep = vmalloc(sz);
	if (NULL == fake_storep) {
		printk(KERN_ERR "scsi_ses_init: out of memory, 1\n");
		return -ENOMEM;
	}
	memset(fake_storep, 0, sz);
	if (scsi_ses_num_parts > 0)
		sses_build_parts(fake_storep);

	init_all_queued();

	if(SES_FALSE == ses_device.initialized)
		initialize_ses_dev(&ses_device);

	device_register(&spseudo_primary);
	bus_register(&spseudo_lld_bus);
	driver_register(&sses_driverfs_driver);
	do_create_driverfs_files();

	sses_driver_template.proc_name = (char *)sses_proc_name;

        host_to_add = scsi_ses_add_host;
        scsi_ses_add_host = 0;

        for (k = 0; k < host_to_add; k++) {
                if (sses_add_adapter()) {
                        printk(KERN_ERR "scsi_ses_init: "
                               "sses_add_adapter failed k=%d\n", k);
                        break;
                }
        }

	if (SCSI_SES_OPT_NOISE & scsi_ses_opts) {
		printk(KERN_INFO "scsi_ses_init: built %d host(s)\n",
		       scsi_ses_add_host);
	}
	return 0;
}

static void __exit scsi_ses_exit(void)
{
	int k = 1;

	stop_all_queued();
	for (; k; k--)
		sses_remove_adapter();
	do_remove_driverfs_files();
	driver_unregister(&sses_driverfs_driver);
	bus_unregister(&spseudo_lld_bus);
	device_unregister(&spseudo_primary);

	vfree(fake_storep);
}

device_initcall(scsi_ses_init);
module_exit(scsi_ses_exit);

void spseudo_0_release(struct device * dev)
{
	if (SCSI_SES_OPT_NOISE & scsi_ses_opts)
		printk(KERN_INFO "scsi_ses: spseudo_0_release() called\n");
}

static struct device spseudo_primary = {
	.bus_id		= "spseudo_0",
	.release	= spseudo_0_release,
};

static int spseudo_lld_bus_match(struct device *dev,
                          struct device_driver *dev_driver)
{
        return 1;
}

static struct bus_type spseudo_lld_bus = {
        .name = "spseudo",
        .match = spseudo_lld_bus_match,
};

static void sses_release_adapter(struct device * dev)
{
        struct sses_host_info *sdbg_host;

	sdbg_host = to_sses_host(dev);
        kfree(sdbg_host);
}

static int sses_add_adapter(void)
{
	int k, devs_per_host;
        int error = 0;
        struct sses_host_info *sdbg_host;
        struct sses_dev_info *sdbg_devinfo;
        struct list_head *lh, *lh_sf;

        sdbg_host = kmalloc(sizeof(*sdbg_host),GFP_KERNEL);

        if (NULL == sdbg_host) {
                printk(KERN_ERR "%s: out of memory at line %d\n",
                       __FUNCTION__, __LINE__);
                return -ENOMEM;
        }

        memset(sdbg_host, 0, sizeof(*sdbg_host));
        INIT_LIST_HEAD(&sdbg_host->dev_info_list);

	devs_per_host = scsi_ses_num_tgts * scsi_ses_max_luns;
        for (k = 0; k < devs_per_host; k++) {
                sdbg_devinfo = kmalloc(sizeof(*sdbg_devinfo),GFP_KERNEL);
                if (NULL == sdbg_devinfo) {
                        printk(KERN_ERR "%s: out of memory at line %d\n",
                               __FUNCTION__, __LINE__);
                        error = -ENOMEM;
			goto clean;
                }
                memset(sdbg_devinfo, 0, sizeof(*sdbg_devinfo));
                sdbg_devinfo->sdbg_host = sdbg_host;
                list_add_tail(&sdbg_devinfo->dev_list,
                              &sdbg_host->dev_info_list);
        }

        spin_lock(&sses_host_list_lock);
        list_add_tail(&sdbg_host->host_list, &sses_host_list);
        spin_unlock(&sses_host_list_lock);

        sdbg_host->dev.bus = &spseudo_lld_bus;
        sdbg_host->dev.parent = &spseudo_primary;
        sdbg_host->dev.release = &sses_release_adapter;
        sprintf(sdbg_host->dev.bus_id, "adapter%d", scsi_ses_add_host);

        error = device_register(&sdbg_host->dev);

        if (error)
		goto clean;

	++scsi_ses_add_host;
        return error;

clean:
	list_for_each_safe(lh, lh_sf, &sdbg_host->dev_info_list) {
		sdbg_devinfo = list_entry(lh, struct sses_dev_info,
					  dev_list);
		list_del(&sdbg_devinfo->dev_list);
		kfree(sdbg_devinfo);
	}

	kfree(sdbg_host);
        return error;
}

static void sses_remove_adapter(void)
{
        struct sses_host_info * sdbg_host = NULL;

        spin_lock(&sses_host_list_lock);
        if (!list_empty(&sses_host_list)) {
                sdbg_host = list_entry(sses_host_list.prev,
                                       struct sses_host_info, host_list);
		list_del(&sdbg_host->host_list);
	}
        spin_unlock(&sses_host_list_lock);

	if (!sdbg_host)
		return;

        device_unregister(&sdbg_host->dev);
        --scsi_ses_add_host;
}

static int sses_driver_probe(struct device * dev)
{
        int error = 0;
        struct sses_host_info *sdbg_host;
        struct Scsi_Host *hpnt;

	sdbg_host = to_sses_host(dev);

        hpnt = scsi_host_alloc(&sses_driver_template, sizeof(sdbg_host));
        if (NULL == hpnt) {
                printk(KERN_ERR "%s: scsi_register failed\n", __FUNCTION__);
                error = -ENODEV;
		return error;
        }

        sdbg_host->shost = hpnt;
	*((struct sses_host_info **)hpnt->hostdata) = sdbg_host;
	if ((hpnt->this_id >= 0) && (scsi_ses_num_tgts > hpnt->this_id))
		hpnt->max_id = scsi_ses_num_tgts + 1;
	else
		hpnt->max_id = scsi_ses_num_tgts;
	hpnt->max_lun = scsi_ses_max_luns;

        error = scsi_add_host(hpnt, &sdbg_host->dev);
        if (error) {
                printk(KERN_ERR "%s: scsi_add_host failed\n", __FUNCTION__);
                error = -ENODEV;
		scsi_host_put(hpnt);
        } else
		scsi_scan_host(hpnt);


        return error;
}

static int sses_driver_remove(struct device * dev)
{
        struct list_head *lh, *lh_sf;
        struct sses_host_info *sdbg_host;
        struct sses_dev_info *sdbg_devinfo;

	sdbg_host = to_sses_host(dev);

	if (!sdbg_host) {
		printk(KERN_ERR "%s: Unable to locate host info\n",
		       __FUNCTION__);
		return -ENODEV;
	}

        scsi_remove_host(sdbg_host->shost);

        list_for_each_safe(lh, lh_sf, &sdbg_host->dev_info_list) {
                sdbg_devinfo = list_entry(lh, struct sses_dev_info,
                                          dev_list);
                list_del(&sdbg_devinfo->dev_list);
                kfree(sdbg_devinfo);
        }

        scsi_host_put(sdbg_host->shost);
        return 0;
}

/**Zacharia Mathew's code follows*/
#define SDEBUG_MAX_RECV_DIAG_ARR_SZ 1000

/* 8 bits used for temperatures in the range -19 C to +235 C. The value of
   0 (otherwise corresponding to -20 C) is reserved. */
#define TEMPERATURE_OFFSET	20


static int resp_send_diag(Scsi_Cmnd *cmd_arg,
			  struct sses_dev_info *devip)
{
        unsigned char arr[SDEBUG_MAX_RECV_DIAG_ARR_SZ];
        int (* fp)(struct ses_dev*, unsigned char*);
        int errno = 0;
	int res;
 
	memset(arr, 0, sizeof(arr));
	res = fetch_to_dev_buffer(cmd_arg, arr, sizeof(arr));
	if (res <= 0) {
                mk_sense_buffer(devip, ILLEGAL_REQUEST, 0x24, 0);
                return check_condition_result;
	}
        switch (arr[0]){
                case ENCLOSURE_CONTROL_DIAGNOSTIC_PAGE:
                case STRING_OUT_DIAGNOSTIC_PAGE:
                case THRESHOLD_OUT_DIAGNOSTIC_PAGE:
			ses_device.prev_send_cmd = arr[0];
			ses_device.buffer_length = SDEBUG_MAX_RECV_DIAG_ARR_SZ;
			fp = ses_device.send_diag_ptr[arr[0]];
			if (fp)
                        	errno = fp(&ses_device, arr);
			else
				errno = -1;
                        break;
                default:
                        errno = -1;
                        break;
        }
        if( errno < 0){
                mk_sense_buffer(devip, ILLEGAL_REQUEST, 0x24, 0);
                return check_condition_result;
        }else{
                return 0;
        }
}
 
static int receive_diagnostic_command(Scsi_Cmnd *cmd_arg,
                                      struct sses_dev_info * devip)
{
        unsigned char arr[SDEBUG_MAX_RECV_DIAG_ARR_SZ];
        unsigned short int length;
	unsigned char *cmd = (unsigned char *)cmd_arg->cmnd;
        int errno = 0;
	int pg_cd;
	int pcv;
        int min_len = SDEBUG_MAX_RECV_DIAG_ARR_SZ;
        int (* fp)(struct ses_dev*, unsigned char*);
/*To simulate busy wait if 'every_nth' != 0 */
        static int cdb_count = 0;
 
        length = (cmd[3] << 8) + cmd[4];
	pcv = cmd[1] & 1;
	min_len = (min_len < length) ? min_len : length;
	pg_cd = cmd[2];
        memset(arr, 0, SDEBUG_MAX_RECV_DIAG_ARR_SZ);
	if ((scsi_ses_every_nth != 0) &&
	    (++cdb_count >= abs(scsi_ses_every_nth))) {
                 cdb_count = 0;
                 if (scsi_ses_every_nth < -1)
                         scsi_ses_every_nth = -1;  /* continue injecting */
                 /* Send a message that device is busy*/
                 ses_device.busy_wait = DEVICE_BUSY;
                 ses_device.recv_diag_ptr[ENCLOSURE_BUSY_DIAGNOSTIC_PAGE](
						&ses_device, arr);
	} else if (0 == pcv) {
		errno = ses_device.recv_diag_ptr[ses_device.prev_send_cmd](
						&ses_device, arr);
	} else {
		switch(pg_cd) {
			case SUPPORTED_DIAGNOSTIC_PAGE:
			case CONFIGURATION_DIAGNOSTIC_PAGE:
			case HELP_TEXT_DIAGNOSTIC_PAGE:
			case STRING_IN_DIAGNOSTIC_PAGE:
			case THRESHOLD_IN_DIAGNOSTIC_PAGE:
			case ELEMENT_DESCRIPTOR_DIAGNOSTIC_PAGE:
			case ENCLOSURE_BUSY_DIAGNOSTIC_PAGE:
			case ENCLOSURE_STATUS_DIAGNOSTIC_PAGE:
				/*Zacharia Mathew 20050112*/
				//ses_device.buffer_length = SDEBUG_MAX_RECV_DIAG_ARR_SZ;
				/*The buffer_lenght variable is added to find out the length of
				  the data user wants from the device. for Enclosure Status 
				  diagnostic page if buffer_length is 0 then it means the 
				  device shall return a short page rather then the usual big page*/
				ses_device.buffer_length = length;
				fp = ses_device.recv_diag_ptr[pg_cd];
				if (fp)
					errno = fp(&ses_device, arr);
				else
					errno = -1;
				break;
/*              case DEVICE_ELEMENT_STATUS_DIAGNOSTIC_PAGE:
			// Implemented later ??
			break;
*/
			default:
				errno = -1;
				break;
       		 }
	}
        if( 0 != errno){
                mk_sense_buffer(devip, ILLEGAL_REQUEST, 0x24, 0);
                return check_condition_result;
        }
        return fill_from_dev_buffer(cmd_arg, arr, min_len);
}


static struct ses_dev_conf ses_dev_conf_t[SCSI_SES_NUM_TYPE_LIST] = {
  /* DEVICE_TYPE  MAX_NUMBER_OF_DEVICES   INSTALLED_NUMBER_OF_DEVICE*/
	{0x02,		4,				2},
	{0x03,		5,				3},
	{0x04,		2,				2}
};



static int initialize_power_device( struct type_list *ptr);
static int initialize_cooling_device( struct type_list *ptr);
static int initialize_temperature_device( struct type_list *ptr);

static int get_support_diagnostic_page( struct ses_dev *ses_device, unsigned char *buffer);

static int get_configuration_diag_page( struct ses_dev *ses_device, unsigned char *buffer);

static int get_stat_diag_page( struct ses_dev *ses_device, unsigned char *buffer);
static int get_stat_device_type( struct ses_dev *ses_device, unsigned char *buffer);
static int get_stat_power_dev( struct power_device *head, unsigned char *buffer);
static int get_stat_cooling_dev( struct cooling_device *head, unsigned char *buffer);
static int get_stat_temp_dev( struct temperature_device *head, unsigned char *buffer);

static int get_help_txt_page( struct ses_dev *ses_device, unsigned char *buffer);

static int get_string_page( struct ses_dev *ses_device, unsigned char *buffer);

static int get_threshold_page( struct ses_dev *ses_device, unsigned char *buffer);
static int fill_threshold_values( struct type_list *head, unsigned char *buffer);
static int fill_temp_threshold( struct temperature_device *dev, unsigned char *buffer);

static int get_element_descriptor( struct ses_dev *ses_device, unsigned char *buffer);

static int get_element_busy_page( struct ses_dev *ses_device, unsigned char *buffer);

static int set_string_page( struct ses_dev *ses_device, unsigned char *buffer);

static int set_threshold_page( struct ses_dev *ses_device, unsigned char *buffer);
static int set_threshold_in_dev( struct type_list *head, unsigned char *buffer);

static int set_configuration_diag_page( struct ses_dev *ses_device, unsigned char *buffer);
static int set_conf_for_dev( struct type_list *head, unsigned char *buffer);
static int set_configuration_power( struct power_device *head, unsigned char *buffer);
static int set_configuration_cooling( struct cooling_device *head, unsigned char *buffer);
static int set_configuration_temp( struct temperature_device *head, unsigned char *buffer);

int initialize_ses_dev( struct ses_dev *ses_device)
{
	/* Support pages*/
	int i = 0;
	char pg_cd[SCSI_SES_MAX_SUPPORT_PAGES] = {0x00,0x01,0x02,0x03,0x04,0x05,0x07,0x09};
	char dev_sp[SCSI_SES_DEV_INFO] = {0xde,0xad,0xbe,0xef,0xab,0xbd};

	memset( ses_device,0,sizeof( struct ses_dev));
	memcpy(ses_device->support_pages,pg_cd,SCSI_SES_MAX_SUPPORT_PAGES);
	memcpy( ses_device->device_specific, dev_sp, SCSI_SES_DEV_INFO);
	ses_device->busy_wait     = DEVICE_NOT_BUSY;
	ses_device->support_flag  = SES_TRUE;
	ses_device->initialized   = SES_TRUE;
	ses_device->num_type_list = SCSI_SES_NUM_TYPE_LIST;
	/*Initialization of the enclosure part*/
	ses_device->enclosure.sub_encl_id        = SCSI_SES_PRIMARY_ENCLOSURE_ID;
	ses_device->enclosure.num_types          = SCSI_SES_NUM_TYPE_LIST       ;
	memcpy( ses_device->enclosure.logical_id,inq_logical_id,strlen(inq_logical_id))   ;
	memcpy( ses_device->enclosure.ses_vendor_id, inq_vendor_id, strlen( inq_vendor_id))   ;
	memcpy( ses_device->enclosure.prod_id, inq_product_id, strlen( inq_product_id))         ;
	memcpy( ses_device->enclosure.prod_level, inq_product_rev, strlen( inq_product_rev));
	/*Initialization of the device list*/
	for( ; i < SCSI_SES_NUM_TYPE_LIST; i++){
		ses_device->head[i].sub_encl_id       = SCSI_SES_PRIMARY_ENCLOSURE_ID;
		ses_device->head[i].select                = 1;
		ses_device->head[i].type                  =  i;
		if( POWER == i)
			initialize_power_device( &( ses_device->head[i]));
		else if( COOLING == i)
			initialize_cooling_device( &( ses_device->head[i]));
		else if( TEMPERATURE_SENSOR == i)
			initialize_temperature_device( &( ses_device->head[i]));
	}	

	ses_device->recv_diag_ptr[ SUPPORTED_DIAGNOSTIC_PAGE]                = get_support_diagnostic_page;
        ses_device->recv_diag_ptr[ CONFIGURATION_DIAGNOSTIC_PAGE] 	      = get_configuration_diag_page;
        ses_device->recv_diag_ptr[ ENCLOSURE_STATUS_DIAGNOSTIC_PAGE]   = get_stat_diag_page;
	ses_device->recv_diag_ptr[ HELP_TEXT_DIAGNOSTIC_PAGE]                  = get_help_txt_page;
	ses_device->recv_diag_ptr[ STRING_IN_DIAGNOSTIC_PAGE]                  = get_string_page;
	ses_device->recv_diag_ptr[ THRESHOLD_IN_DIAGNOSTIC_PAGE]            = get_threshold_page;
	ses_device->recv_diag_ptr[ ELEMENT_DESCRIPTOR_DIAGNOSTIC_PAGE] = get_element_descriptor; 
	ses_device->recv_diag_ptr[ ENCLOSURE_BUSY_DIAGNOSTIC_PAGE]        = get_element_busy_page;

	ses_device->send_diag_ptr[ STRING_OUT_DIAGNOSTIC_PAGE]               = set_string_page;
	ses_device->send_diag_ptr[ THRESHOLD_OUT_DIAGNOSTIC_PAGE]         = set_threshold_page;
	ses_device->send_diag_ptr[ ENCLOSURE_CONTROL_DIAGNOSTIC_PAGE] = set_configuration_diag_page;
	return 0;
}


static int initialize_power_device( struct type_list *power_dev)
{
	int i;

	power_dev->desc = "Imaginary power element to check the ses system:ver-1.1.2:";
	power_dev->dev_sp.power = kmalloc( sizeof( struct power_device) * 
					   ses_dev_conf_t[ POWER].max, GFP_KERNEL);
	memset( power_dev->dev_sp.power, 0, 
		sizeof( struct power_device) * ses_dev_conf_t[ POWER].max);
	
	for( i = 0; i < ses_dev_conf_t[ POWER].installed; i++){
		power_dev->dev_sp.power[i].select            = 1;
		power_dev->dev_sp.power[i].predicted_failure = 1;
		power_dev->dev_sp.power[i].status            = OK;
		power_dev->dev_sp.power[i].identify          = 1; 
		power_dev->dev_sp.power[i].latch             = SES_FALSE;
	}
	for( ; i < ses_dev_conf_t[ POWER].max; i++)
		power_dev->dev_sp.power[i].status = NOT_INSTALLED;

	return 0;
}


static int initialize_cooling_device( struct type_list *cooling_dev)
{

	int i;

	cooling_dev->desc = "Imaginary cooling element to check the ses system:ver-1.1.2:";
	cooling_dev->dev_sp.cooling = kmalloc( sizeof( struct cooling_device) * 
				  	       ses_dev_conf_t[ COOLING].max, GFP_KERNEL);
	memset( cooling_dev->dev_sp.cooling, 0, 
		sizeof( struct cooling_device) * ses_dev_conf_t[ COOLING].max);				
 
	for( i = 0; i < ses_dev_conf_t[ COOLING].installed; i++){
		cooling_dev->dev_sp.cooling[i].predicted_failure = 1;
		cooling_dev->dev_sp.cooling[i].select            = 1;
		cooling_dev->dev_sp.cooling[i].status            = OK;
		cooling_dev->dev_sp.cooling[i].identify          = 1; 
		cooling_dev->dev_sp.cooling[i].fan_speed         = 20;
		cooling_dev->dev_sp.cooling[i].speed             = LOWEST_SPEED;
	}
	for( ; i < ses_dev_conf_t[ COOLING].max; i++)
		cooling_dev->dev_sp.cooling[i].status = NOT_INSTALLED;

	return 0;
}


static int initialize_temperature_device( struct type_list *temp_dev)
{

	int i;

	temp_dev->device_dep_field.temp_var.high_critical = 65 + TEMPERATURE_OFFSET;
	temp_dev->device_dep_field.temp_var.high_warning  = 55 + TEMPERATURE_OFFSET;
	temp_dev->device_dep_field.temp_var.low_warning   = 5 + TEMPERATURE_OFFSET;
	temp_dev->device_dep_field.temp_var.low_critical  = 0 + TEMPERATURE_OFFSET;
	temp_dev->desc = "Imaginary temperature element to check the ses system:ver-1.1.2";
	temp_dev->dev_sp.temperature = kmalloc( sizeof( struct temperature_device) * 
						ses_dev_conf_t[ TEMPERATURE_SENSOR].max, GFP_KERNEL);
	memset( temp_dev->dev_sp.temperature, 0,
		sizeof( struct temperature_device) * ses_dev_conf_t[ TEMPERATURE_SENSOR].max);

	for( i = 0; i < ses_dev_conf_t[TEMPERATURE_SENSOR].installed; i++){
		temp_dev->dev_sp.temperature[i].predicted_failure = 1;
		temp_dev->dev_sp.temperature[i].high_critical     = 65 + TEMPERATURE_OFFSET;
		temp_dev->dev_sp.temperature[i].high_warning      = 55 + TEMPERATURE_OFFSET;
		temp_dev->dev_sp.temperature[i].low_warning      = 5 + TEMPERATURE_OFFSET;
		temp_dev->dev_sp.temperature[i].low_critical     = 0 + TEMPERATURE_OFFSET;
		temp_dev->dev_sp.temperature[i].select            = 1;
		temp_dev->dev_sp.temperature[i].status            = OK;
		temp_dev->dev_sp.temperature[i].identify          = 1; 
		temp_dev->dev_sp.temperature[i].temperature       = 32 + i + TEMPERATURE_OFFSET;
	}
	for( ;i < ses_dev_conf_t[ TEMPERATURE_SENSOR].max; i++)
		temp_dev->dev_sp.temperature[i].status = NOT_INSTALLED;

	return 0;
}

static int get_support_diagnostic_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	if( SES_FALSE == ses_device->support_flag){
		printk(KERN_INFO" support flags = 0, Device doent support page formats\n");
		return -1;
	}else{
		buffer[0] = SUPPORTED_DIAGNOSTIC_PAGE;
		buffer[3] = SCSI_SES_MAX_SUPPORT_PAGES;
		memcpy( &buffer[4], ses_device->support_pages, SCSI_SES_MAX_SUPPORT_PAGES);
	}
	return 0;
}

static int get_configuration_diag_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	int n = 48;
	int i = 0;
	 
	buffer[0] = CONFIGURATION_DIAGNOSTIC_PAGE;
	buffer[1] = SCSI_SES_NUM_SUB_ENCLOSURES;
	buffer[4] = (ses_device->gen_cd >> 24) & 0xff;
	buffer[5] = (ses_device->gen_cd >> 16) & 0xff;
	buffer[6] = (ses_device->gen_cd >> 8) & 0xff;
	buffer[7] = ses_device->gen_cd & 0xff;
	
	buffer[8] = ( ( unsigned char)( ses_device->enclosure.rel_encl_serv_id << 4) | \
		    ( unsigned char)( ses_device->enclosure.rel_rncl_serv_proc)) & 0x77;
	buffer[9] = ses_device->enclosure.sub_encl_id;
	buffer[10] = ses_device->enclosure.num_types;
	buffer[11] = 36;/*Debug device*/
	memcpy( &buffer[12], ses_device->enclosure.logical_id, 8);
	memcpy( &buffer[20], ses_device->enclosure.ses_vendor_id, 8);
	memcpy( &buffer[28], ses_device->enclosure.prod_id,16);
	memcpy( &buffer[44], ses_device->enclosure.prod_level, 4);

	for( ; i < SCSI_SES_NUM_TYPE_LIST; i++){
		int len = strlen( ses_device->head[i].desc);
		while( len%4)
			len++;
		buffer[n++] = ses_dev_conf_t[ ses_device->head[i].type].ses_dev_t;
		buffer[n++] = ses_dev_conf_t[ ses_device->head[i].type].max;
		buffer[n++] = ses_device->head[i].sub_encl_id;
		buffer[n++] = len;
	}

	for( i = 0; i < SCSI_SES_NUM_TYPE_LIST; i++){
		memcpy( &buffer[n], ses_device->head[i].desc, strlen( ses_device->head[i].desc));
		n += strlen( ses_device->head[i].desc);
		PADDING( buffer, n);
	}
	n -= 4;
	buffer[2] = (n >> 8) & 0xff;
	buffer[3] = n & 0xff;
	return 0;
}

static int get_stat_diag_page( struct ses_dev *ses_device, unsigned char *buffer)
{ 
	int n = 0;
	int len = ses_device->buffer_length;

	buffer[0]  = ENCLOSURE_STATUS_DIAGNOSTIC_PAGE;
	buffer[1]  = ( unsigned char)(0x10 & (ses_device->invalid_op << 4));
	buffer[1] |= ( unsigned char)(0x08 & (ses_device->info << 3));
	buffer[1] |= ( unsigned char)(0x04 & (ses_device->non_critical << 2));
	buffer[1] |= ( unsigned char)(0x02 & (ses_device->critical) << 1);
	buffer[1] |= ( unsigned char)(0x01 & (ses_device->unrecoverable));
	printk(KERN_ALERT"length = %d\n", len);

	if( len != 0){
		buffer[4] = (ses_device->gen_cd >> 24) & 0xff;
		buffer[5] = (ses_device->gen_cd >> 16) & 0xff;
		buffer[6] = (ses_device->gen_cd >> 8) & 0xff;
		buffer[7] = ses_device->gen_cd & 0xff;
		n += get_stat_device_type( ses_device, &buffer[8]);
		n += 4;
	}
	buffer[2] = (n >> 8) & 0xff;
	buffer[3] = n & 0xff;
	return 0;
}

static int get_stat_device_type( struct ses_dev *ses_device, unsigned char *buffer)
{
	int i = 0;
	int n = 0;

	for( ; i < SCSI_SES_NUM_TYPE_LIST; i++){
		buffer[n]  = ( ( ses_device->head[i].predicted_failure) << 6) & 0x40;
		buffer[n] |= ( ( ses_device->head[i].reset_swap) << 4) & 0x10;
		buffer[n] |= UNSUPPORTED & 0x0f;
		n += 4;
		if( POWER == ses_device->head[i].type)
			n += get_stat_power_dev( ses_device->head[i].dev_sp.power, &buffer[n]);
		else if( COOLING == ses_device->head[i].type)
			n += get_stat_cooling_dev( ses_device->head[i].dev_sp.cooling, &buffer[n]);
		else if( TEMPERATURE_SENSOR == ses_device->head[i].type)
			n += get_stat_temp_dev( ses_device->head[i].dev_sp.temperature, &buffer[n]);
	}
	return n;	
}

static int get_stat_power_dev( struct power_device *power, unsigned char *buffer)
{
	int i = 0;
	int n = 0;
	for( ; i < ses_dev_conf_t[ POWER].max; i++, n += 4){
		buffer[n]  = ( ( power[i].predicted_failure) << 6) & 0x40;
		buffer[n] |= ( ( power[i].swap) << 4) & 0x10;
		buffer[n] |= power[i].status & 0x0f;
		if( NOT_INSTALLED == power[i].status)
			continue;
		buffer[n+1]  = (power[i].identify << 7) & 0x80;
		buffer[n+2]  = (power[i].dc_over_volt << 3) & 0x08;
		buffer[n+2] |= (power[i].dc_under_volt << 2) & 0x04;
		buffer[n+2] |= (power[i].dc_over_curr << 1) & 0x02;
		buffer[n+3]  = (power[i].fail << 6) & 0x40;
		buffer[n+3] |= (power[i].req_on << 5) & 0x20;
		buffer[n+3] |= (power[i].off << 4) & 0x10;
		buffer[n+3] |= (power[i].over_temp_fail << 3) & 0x08;
		buffer[n+3] |= (power[i].temp_warn << 2) & 0x04;
		buffer[n+3] |= (power[i].ac_fail << 1) & 0x02;
		buffer[n+3] |= (power[i].dc_fail) & 0x01;
	}
	return 4 * ses_dev_conf_t[ POWER].max;
}

static int get_stat_cooling_dev( struct cooling_device *cooling, unsigned char *buffer)
{
	int i = 0;
	int n = 0;
	for( ; i < ses_dev_conf_t[ COOLING].max; i++, n += 4){
		buffer[n]  = ( ( cooling[i].predicted_failure) << 6) & 0x40;
		buffer[n] |= ( ( cooling[i].swap) << 4) & 0x10;
		buffer[n] |= cooling[i].status & 0x0f;
		if( NOT_INSTALLED == cooling[i].status)
			continue;
		buffer[n+1]  = (cooling[i].identify << 7) & 0x80;
		buffer[n+2]  = (cooling[i].fan_speed);
		buffer[n+3]  = (cooling[i].fail << 6) & 0x40;
		buffer[n+3] |= (cooling[i].req_on << 5) & 0x20;
		buffer[n+3] |= (cooling[i].off << 4) & 0x10;
		buffer[n+3] |= (cooling[i].speed) & 0x07;
	}
	return 4 * ses_dev_conf_t[ COOLING].max;
}

static int get_stat_temp_dev( struct temperature_device *temperature, unsigned char *buffer)
{
	int i = 0;
	int n = 0;

	for( ; i < ses_dev_conf_t[ TEMPERATURE_SENSOR].max; i++, n += 4){
		buffer[n]  = ( ( temperature[i].predicted_failure) << 6) & 0x40;
		buffer[n] |= ( ( temperature[i].swap) << 4) & 0x10;
		buffer[n] |= temperature[i].status & 0x0f;
		if( NOT_INSTALLED == temperature[i].status)
			continue;
		buffer[n+1]  = ( temperature[i].identify << 7) & 0x80;
		buffer[n+2]  = ( temperature[i].temperature);
		buffer[n+3]  = ( temperature[i].over_temp_fail << 3) & 0x08;
		buffer[n+3]  = ( temperature[i].over_temp_warn << 2) & 0x04;
		buffer[n+3]  = ( temperature[i].under_temp_fail << 1) & 0x02;
		buffer[n+3]  = ( temperature[i].under_temp_warn) & 0x01;
	}	
	return 4 * ses_dev_conf_t[ TEMPERATURE_SENSOR].max;
}

static int get_help_txt_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	char *ptr = "Reset the device, Switch off the power for 10 min";
	int len = strlen( ptr);

	buffer[0] = HELP_TEXT_DIAGNOSTIC_PAGE;
	memcpy ( &buffer[4], ptr, len);
	len += 4;
	PADDING( buffer, len);
	len -= 4;
	buffer[2] = (len >> 8) & 0xff;
	buffer[3] = len & 0xff;

	return 0;
}

static int get_string_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	buffer[0] = STRING_IN_DIAGNOSTIC_PAGE;
	buffer[2] = (SCSI_SES_DEV_INFO >> 8) & 0xff;
	buffer[3] = SCSI_SES_DEV_INFO & 0xff;
	memcpy( &buffer[4], ses_device->device_specific, SCSI_SES_DEV_INFO);
	return 0;
}

static int get_threshold_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	int i = 0;
	int n = 0;

	buffer[0] = THRESHOLD_IN_DIAGNOSTIC_PAGE;
	buffer[1] = (unsigned char)((ses_device->invalid_op << 4) & 0x10); 

	buffer[4] = (ses_device->gen_cd >> 24) & 0xff;
	buffer[5] = (ses_device->gen_cd >> 16) & 0xff;
	buffer[6] = (ses_device->gen_cd >> 8) & 0xff;
	buffer[7] = ses_device->gen_cd & 0xff;
	
	for(n = 8; i < SCSI_SES_NUM_TYPE_LIST; i++)
		n += fill_threshold_values( &( ses_device->head[i]), &buffer[n]);
	n -= 4;
	buffer[2] = (n >> 8) & 0xff;
	buffer[3] = n & 0xff;
	return 0;
}

static int fill_threshold_values( struct type_list *head, unsigned char *buffer)
{
	memset( buffer, 0, ses_dev_conf_t[ head->type].max * 4 + 4);
	if( TEMPERATURE_SENSOR == head->type){
		buffer[0] = head->device_dep_field.temp_var.high_critical;
		buffer[1] = head->device_dep_field.temp_var.high_warning;
		buffer[2] = head->device_dep_field.temp_var.low_warning;
		buffer[3] = head->device_dep_field.temp_var.low_critical;
		fill_temp_threshold( head->dev_sp.temperature, &buffer[4]);
	}
	return 4 * ses_dev_conf_t[ head->type].max + 4;
}

static int fill_temp_threshold( struct temperature_device *temperature, unsigned char *buffer)
{
	int i = 0;
	int n;
	for(n = 0; i < ses_dev_conf_t[ TEMPERATURE_SENSOR].max; i++){
		buffer[n++] = temperature[i].high_critical;
		buffer[n++] = temperature[i].high_warning;
		buffer[n++] = temperature[i].low_warning;
		buffer[n++] = temperature[i].low_critical;
	}
	return n;
}

static int get_element_descriptor( struct ses_dev *ses_device, unsigned char *buffer)
{
	int i = 0;
	int n = 0;

	buffer[0] = ELEMENT_DESCRIPTOR_DIAGNOSTIC_PAGE; 
	buffer[4] = (ses_device->gen_cd >> 24) & 0xff;
	buffer[5] = (ses_device->gen_cd >> 16) & 0xff;
	buffer[6] = (ses_device->gen_cd >> 8) & 0xff;
	buffer[7] = ses_device->gen_cd & 0xff;

	for( n = 8; i < SCSI_SES_NUM_TYPE_LIST; i++){
		int j,k;
		buffer[n] = buffer[n + 1] = 0;
		n += 4;
		k = n;
		strcpy( &buffer[n],ses_device->head[i].desc);
		n += strlen( &buffer[n]);
		PADDING( buffer, n);
		buffer[k - 2] = ((n - k) >> 8) & 0xff;
		buffer[k - 1] = (n - k) & 0xff;
		for(j = ses_dev_conf_t[ ses_device->head[ i].type].max; j--; n += 4)
			memset( &buffer[n], 0, 4);
	}
	n += 4;
	buffer[2] = (n >> 8) & 0xff;
	buffer[3] = n & 0xff;
	return 0;
}

static int get_element_busy_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	buffer[0] = ENCLOSURE_BUSY_DIAGNOSTIC_PAGE; 
	buffer[1] = ses_device->busy_wait; 
	ses_device->busy_wait = DEVICE_NOT_BUSY; 
	return 0;
}

static int set_string_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	if( ses_device->buffer_length > SCSI_SES_DEV_INFO)
		return -1;
	memcpy( ses_device->device_specific, &buffer[4], SCSI_SES_DEV_INFO);
	return 0;
}

static int set_threshold_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	int i = 0;
	int num = 7;

	//for( ; i < SCSI_SES_NUM_TYPE_LIST; i++)
	//	tmp += ( 4 * ses_dev_conf_t[ i].max + 4);
	//if( tmp > ses_device->buffer_length)
	//	return -1;
	for( ; i < SCSI_SES_NUM_TYPE_LIST; i++){
		if( ses_device->head[i].type == TEMPERATURE_SENSOR){
			if( buffer[ ++num] != 0)
				ses_device->head[i].device_dep_field.temp_var.high_critical = buffer[ num];
			if( buffer[ ++num] != 0)
				ses_device->head[i].device_dep_field.temp_var.high_warning  = buffer[ num];
			if( buffer[ ++num] != 0)
				ses_device->head[i].device_dep_field.temp_var.low_warning   = buffer[ num];
			if( buffer[ ++num] != 0) 
				ses_device->head[i].device_dep_field.temp_var.low_critical  = buffer[ num];
			set_threshold_in_dev( &( ses_device->head[i]), &buffer[ ++num]);
			break;
		}else
			num += ( 4 * ses_dev_conf_t[ i].max + 4);
	}
	
	return 0;
}

static int set_threshold_in_dev( struct type_list *head, unsigned char *buffer)
{
	int i = 0;
	int n = -1;

	for(; i < ses_dev_conf_t[ head->type].max; i++){
		if( head->dev_sp.temperature[i].status == NOT_INSTALLED){
			n += 4;
			continue;
		}
		if( buffer[++n] != 0)
			head->dev_sp.temperature[i].high_critical = buffer[n];
		if( buffer[++n] != 0)
			head->dev_sp.temperature[i].high_warning  = buffer[n];
		if( buffer[++n] != 0)
			head->dev_sp.temperature[i].low_warning   = buffer[n];
		if( buffer[++n] != 0)
			head->dev_sp.temperature[i].low_critical  = buffer[n];
	}
	return 0;
}

static int set_configuration_diag_page( struct ses_dev *ses_device, unsigned char *buffer)
{
	int n = 1;
	unsigned long ul;

	//for( ; i < SCSI_SES_NUM_TYPE_LIST; i++)
	//	tmp += ( 4 * ses_dev_conf_t[ i].max + 4);
	//if( ses_device->buffer_length < tmp)
	//	return -1;

	ses_device->info          = buffer[ n++] & 0x08;
	ses_device->non_critical  = buffer[ n++] & 0x04;
	ses_device->critical      = buffer[ n++] & 0x02;
	ses_device->unrecoverable = buffer[ n++] & 0x01;

	ul = (buffer[4] << 24) + (buffer[5] << 16) + (buffer[6] << 8) + buffer[7];
	if( ses_device->gen_cd != ul )
		return -1;
	n = set_conf_for_dev( ses_device->head, &buffer[8]);
	return 0;
}

static int set_conf_for_dev( struct type_list *head, unsigned char *buffer)
{
	int i = 0;
	int n = 4;

	for( ; i < SCSI_SES_NUM_TYPE_LIST; i++){
		switch( head[i].type){
			case POWER:
				n += set_configuration_power( head[i].dev_sp.power, &buffer[ n]);
				break;
			case COOLING:
				n += set_configuration_cooling( head[i].dev_sp.cooling, &buffer[ n]);
				break;
			case TEMPERATURE_SENSOR:
				n += set_configuration_temp( head[i].dev_sp.temperature, &buffer[ n]);
				break;
		}
		n += 4;
	}
	return 0;
}

static int set_configuration_power( struct power_device *power, unsigned char *buffer)
{
	int i = 0;
	int n = 0;

	for( ; i < ses_dev_conf_t[ POWER].max; i++, n += 4){
		if( NOT_INSTALLED == power[i].status)
			continue;
		if( buffer[ n] & 0x80){
			power[i].select = !!(buffer[n] & 0x80);
			power[i].predicted_failure = !!(buffer[n] & 0x40);
			power[i].identify = (buffer[ n + 1] & 0x80) >> 7;
			if( ( buffer[n] & 0x10) && ( 1 == power[i].swap))/*Zacharia 20050210*/
				power[i].swap = 0; 
			if( buffer[ n + 3] & 0x40){
				power[i].latch = SES_TRUE;
			}else if( SES_TRUE == power[i].latch){
				power[i].dc_over_volt   = 0;
				power[i].dc_under_volt  = 0;
				power[i].dc_over_curr   = 0;
				power[i].over_temp_fail = 0;
				power[i].latch          = SES_FALSE;
			}else{
				power[i].latch= SES_FALSE;
				power[i].fail = 0;
			}
			if( buffer[ n+3] & 0x20){
				power[i].req_on = 1;
			}else{
				power[i].req_on = 0;
				power[i].off    = 0;
			}
		}
	}
	return n;
}

static int set_configuration_cooling( struct cooling_device *cooling, unsigned char *buffer)
{
	int i = 0;
	int n = 0;

	for( ; i < ses_dev_conf_t[ COOLING].max; i++, n += 4){
		if( NOT_INSTALLED == cooling[i].status)
			continue;
		if( buffer[ n] & 0x80){
			cooling[i].select            = !!(buffer[n] & 0x80);
			cooling[i].predicted_failure = !!(buffer[n] & 0x40);
			if( ( buffer[n] & 0x10) && ( 1 == cooling[i].swap))/*Zacharia 20050210*/
				cooling[i].swap = 0;
			cooling[i].identify = (buffer[ n + 1] & 0x80) >> 7;
			cooling[i].fail = (buffer[ n+3] & 0x40) >> 6 ;
			if( buffer[ n+3] & 0x20){
				cooling[i].req_on = 1;
			}else{
				cooling[i].req_on = 0;
				cooling[i].off    = 0;
			}
			if( buffer[ n + 3] & 0x07){
				cooling[i].fan_speed *= ( buffer[ n + 3] & 0x07);
				cooling[i].speed     = MIDDLE_SPEED;
			}
		}
	}
	return n;
}

static int set_configuration_temp( struct temperature_device *temperature, unsigned char *buffer)
{
	int i = 0;
	int n = 0;

	for( ; i < ses_dev_conf_t[ TEMPERATURE_SENSOR].max; i++, n += 4){
		if( NOT_INSTALLED == temperature[i].status)
			continue;
		if( buffer[ n] & 0x80){
			temperature[i].select = !!(buffer[n] & 0x80);
			temperature[i].predicted_failure = !!(buffer[n] & 0x40);
			temperature[i].disable = !!(buffer[n] & 0x20);
			if( ( buffer[n] & 0x10) && ( 1 == temperature[i].swap))/*Zacharia 20050210*/
				temperature[i].swap = 0;
			temperature[i].identify = (buffer[ n + 1] & 0x80) >> 7;
		}
	}
	return n;
}


