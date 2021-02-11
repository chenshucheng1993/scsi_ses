#ifndef _SCSI_SES_H
#define _SCSI_SES_H
/*
 * scsi_ses.h  Header file for scsi_ses target enclosure simulator for
 * lk 2.6 series.
 */


#define SCSI_SES_MAX_SUPPORT_PAGES				8

#define SCSI_SES_NUM_TYPE_LIST					3
#define POWER							0
#define COOLING							1
#define TEMPERATURE_SENSOR					2

#define SCSI_SES_MAX_COMMANDS					11
#define SCSI_SES_PRIMARY_ENCLOSURE_ID				0
#define SCSI_SES_NUM_SUB_ENCLOSURES				0
#define SCSI_SES_DEFAULT_NUM_DEVICE				5
#define SCSI_SES_DEV_INFO					10


#define SUPPORTED_DIAGNOSTIC_PAGE				0x00
#define CONFIGURATION_DIAGNOSTIC_PAGE				0x01
#define ENCLOSURE_STATUS_DIAGNOSTIC_PAGE			0x02
#define HELP_TEXT_DIAGNOSTIC_PAGE				0x03
#define STRING_IN_DIAGNOSTIC_PAGE				0x04
#define THRESHOLD_IN_DIAGNOSTIC_PAGE				0x05
#define ELEMENT_DESCRIPTOR_DIAGNOSTIC_PAGE			0x07
#define ENCLOSURE_BUSY_DIAGNOSTIC_PAGE				0x09
#define DEVICE_ELEMENT_STATUS_DIAGNOSTIC_PAGE			0x0a
#define ENCLOSURE_CONTROL_DIAGNOSTIC_PAGE			0x02
#define STRING_OUT_DIAGNOSTIC_PAGE				0x04
#define THRESHOLD_OUT_DIAGNOSTIC_PAGE				0x05

#define DEVICE_BUSY						0xf1
#define DEVICE_NOT_BUSY						0xf0 

#define PADDING( arr, n)	\
		while( n%4 )	\
			arr[n++] = 0;

struct ses_dev_conf{
	unsigned char ses_dev_t;
	unsigned char max;
	unsigned char installed;
};

typedef enum{
	UNSUPPORTED = 0x00,
	OK,
	CRITICAL,
	NONCRITICAL,
	UNRECOVERABLE,
	NOT_INSTALLED,
	UNKNOWN,
	NOT_AVAILABLE,	
	RESERVED
}element_status_code_t;

typedef enum{
	STOP = 0x00,
	LOWEST_SPEED,
	IInd_LOWEST_SPEED,
	IIIrd_LOWEST_SPEED,
	MIDDLE_SPEED,
	IIIrd_HIGHEST_SPEED,
	IInd_HIGHEST_SPEED,
	HIGHEST_SPEED
}act_speed_code_t;

typedef enum{
	SES_FALSE,
	SES_TRUE
}boolean_t;

struct enc_id{
	unsigned char rel_encl_serv_id;
	unsigned char rel_rncl_serv_proc;
	unsigned char sub_encl_id;
	unsigned char num_types;
	unsigned char logical_id[8];
	unsigned char ses_vendor_id[8];
	unsigned char prod_id[16];
	unsigned char prod_level[4];
};

struct power_device{
	unsigned char select;		
	unsigned char predicted_failure;
	unsigned char swap;
	element_status_code_t status;
	unsigned char identify;
	unsigned char dc_over_volt;
	unsigned char dc_under_volt;
	unsigned char dc_over_curr;
	boolean_t latch;
	unsigned char fail;
	unsigned char req_on;
	unsigned char off;
	unsigned char over_temp_fail;
	unsigned char temp_warn;
	unsigned char ac_fail;
	unsigned char dc_fail;
};

struct cooling_device{
	unsigned char		select;
	unsigned char		predicted_failure;
	unsigned char		swap;
	element_status_code_t	status;
	unsigned char		identify;
	unsigned char		fan_speed;
	unsigned char		fail;
	unsigned char		req_on;
	unsigned char		off;
	act_speed_code_t	speed;
};

struct temperature_device{
	unsigned char		high_critical;	
	unsigned char		high_warning;
	unsigned char		low_warning;
	unsigned char		low_critical;	
	unsigned char		select;		
	unsigned char		predicted_failure;
	unsigned char		disable;		
	unsigned char		swap;		
	element_status_code_t	status;
	unsigned char		identify;		
	unsigned char		temperature;	
	unsigned char		over_temp_fail;	
	unsigned char		over_temp_warn;
	unsigned char		under_temp_fail;
	unsigned char		under_temp_warn;
};

struct type_list{
	unsigned char type;
	unsigned char sub_encl_id;
	unsigned char *desc;
	unsigned char select;
	unsigned char predicted_failure;
	unsigned char disable;
	unsigned char reset_swap;
	union{
		struct temperature_device_dep{
			unsigned char high_critical;
			unsigned char high_warning;
			unsigned char low_warning;
			unsigned char low_critical;
		}temp_var;
	}device_dep_field;
	union {
		struct power_device *power;
		struct cooling_device *cooling;
		struct temperature_device *temperature;
	}dev_sp;
};

struct ses_dev{
	unsigned char     support_pages[SCSI_SES_MAX_SUPPORT_PAGES];
	unsigned char     device_specific[SCSI_SES_DEV_INFO];
	unsigned int      buffer_length;
	boolean_t         support_flag;
	boolean_t         initialized;
	boolean_t         busy_wait;
	unsigned char     prev_send_cmd;
	unsigned long int gen_cd;
	unsigned char     invalid_op;
	unsigned char     info;
	unsigned char     non_critical;
	unsigned char     critical;
	unsigned char     unrecoverable;
	unsigned int      num_type_list;
	struct enc_id     enclosure;
	struct type_list  head[ SCSI_SES_NUM_TYPE_LIST];
	int ( *recv_diag_ptr[ENCLOSURE_BUSY_DIAGNOSTIC_PAGE])(struct ses_dev*, unsigned char*);
	int ( *send_diag_ptr[THRESHOLD_OUT_DIAGNOSTIC_PAGE])(struct ses_dev*, unsigned char*);
}; 


#define SCSI_SES_CANQUEUE  255 	/* needs to be >= 1 */

#define SCSI_SES_MAX_CMD_LEN 16

#endif
