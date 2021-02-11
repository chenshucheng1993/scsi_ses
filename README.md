Scsi_ses adapter driver for lk 2.6
Scsi_ses adapter driver for lk 2.6
Introduction
Parameters
Supported SCSI commands
Supported SES Diagnostic pages
Usage
Downloads
Introduction
SCSI Enclosure Services (SES) permit the management and sense the state of power supplies, cooling devices, displays, indicators, individual drives, and other non-SCSI elements installed in an enclosure. The scsi_ses adapter driver simulates a SES device. The default action is to appear as a disk (actually an 8 MB ramdisk) with associated Enclosure Services. This is similar to a fibre channel disk with a SCA-2 connector which includes an Enclosure Services Interface (ESI). Alternatively this driver can simulate a simple SES device.

This linux kernel driver supports recent 2.6 series kernels (2.6.16 at this time). It is closely related to the scsi_debug driver which simulates one or more (ram) disks. The code base of the two drivers is similar. Almost all SES features are accessed via the SCSI SEND DIAGNOSTIC and RECEIVE DIAGNOSTIC RESULTS commands.

The major reference document for this driver is the SES-2 draft standard (revision 10 at this time) which can be found at www.t10.org .
This page describes version 1.05 of the scsi_ses driver. See downloads section below.
Parameters
Here is a list of scsi_ses specific driver parameters:

Parameter name
default value
sysfs access
sysfs write effect
notes
delay
1
read-write
next command
units are jiffies (typically 1 ms)
dev_size_mb
8
read only
-
units are megabytes (2**20 bytes)
every_nth
0
read-write
n commands from now
for "busy" injection: 0 -> off
num_parts
0
read only
-	number of partitions
opts
0
read-write
usually following commands
0 -> quiet and no error injection
scsi_level
5  (spc-2)
read only
-
0 (no compliance), 1, 2, 3 (SCSI-2), 4, 5, 6 and 7 are valid
ses_only
0
read-write
changes command set recognised
0 -> disk with enclosure services
1-> SES device only

The parameter name given in the above table is the module parameter name and the sysfs file name. The boot time parameter (if the scsi_ses driver is built into the kernel) has "scsi_ses." prepended to it. Hence the boot time parameter corresponding to ses_only is scsi_ses.ses_only  .

When the scsi_ses module is loaded, two or more parameters can be given separated by spaces: for example too slow down command responses and appear as a simple SES device: "modprobe scsi_ses delay=100 ses_only=1" could be used.

Sysfs parameters associated with this driver can be found at two locations currently:
/sys/module/scsi_ses/parameters
/sys/bus/spseudo/drivers/scsi_ses
This may be simplified to just the first location in the future. Both directories contain the parameters in the table above. Parameters can be read with the cat command and written with the echo command. Examples:
# cat dev_size_mb
8
# echo 1 > opts

The delay parameter is the number of jiffies by which the driver will delay responses. The default is 1 jiffy. Setting this parameter to 0 (or negative) will cause the response to be sent back to the mid level before the request function is completed. Currently the "jiffy" is a kernel space jiffy (i.e. HZ == 1 millisecond on i386) rather than a user space jiffy (i.e. USER_HZ == 10 milliseconds on i386). This may change. Both delayed and immediate responses are permitted however delayed responses are more realistic. For delayed responses, a kernel timer is used. [Real adapters would generate an interrupt when the response was ready (i.e. the command had completed).] For a fast ram disk set the delay parameter to 0. These SCSI commands ignore the delay parameter and respond immediately: INQUIRY, REPORT LUNS and SYNCHRONIZE CACHE.
The dev_size_mb parameter allows the user to specify the size of the simulated storage. The unit is megabytes and the default value is 8 (megabytes). The maximum value depends on the capabilities of the vmalloc() call on the target architecture. If the module fails to load with a "cannot allocate memory" message then a "vmalloc=nn{KMG}" boot time argument may be needed. [See the kernel source file: Documentation/kernel-parameters.txt for more information on this.] The RAM reserved for storage is initialized to zeros which leads the sd (scsi disk) driver and the block layer to believe there is no partition table present. Partitions can be simulated with num_parts (see below). If a value of 0 or less is given then dev_size_mb is forced to 1 so 1 MB of RAM is used.
The every_nth parameter takes a decimal number as an argument. When this number is greater than zero, then incoming RECEIVE DIAGNOSTIC RESULTS commands are counted and when <n> is reached then an "Enclosure busy" diagnostic page response is sent (irrespective of the diagnostic page requested).  This simulates the enclosure services processor being busy and unable to respond to the requested diagnostic page.  Once the command count reaches <n> then it is reset to zero. For example setting every_nth to 3 will cause every third RECEIVE DIAGNOSTIC RESULTS command to respond with an "enclosure busy" diagnostic page. If every_nth is not given it is defaulted to 0 .
If every_nth is negative then an internal RECEIVE DIAGNOSTIC RESULTS command counter counts down to that value and when it is reached, continually responds with an  "Enclosure busy" diagnostic page. The driver flags this continual "busy" state by setting every_nth to -1 . The user can stop "enclosure busy" diagnostic page response by writing 0 to every_nth .
The num_parts parameter writes a partition table to the ramdisk if the parameter's value is greater than 0. The default is 0 so in that case the ramdisk is simply all zeros. When num_parts is greater than zero a DOS format primary partition block is written to logical block 0, so the number of partitions is limited to a maximum of 4. The partitions are given an id of 0x83 which is a "Linux" partition. The available space on the ramdisk is roughly divided evenly between partitions when 2 or more partitions are requested. The partitions are not initialized with any file system. Even if no partitions are specified, a utility like fdisk can be used to added them later.

The opts parameter takes a  number as an argument which is the bitwise "or" of several flags. Only one flag is currently supported:
    1  -  "noisy" flag: all calls to entry points of driver are logged. Commands to be executed are shown in hex.
The "noisy" (or debug) flag will cause all scsi_ses entry points to be logged in the system log (and often sent to the console depending on how kernel informational messages are processed). With this flag commands are listed in hex and if they yield a result other than successful then that is shown. A minor point: the kernel boot time and module load time opts parameter is a decimal integer. However the output sysfs value is a hexadecimal number (output as 0x9 for example) while the input value is interpreted as hexadecimal if prefixed by "0x" and decimal otherwise. The sysfs handling reflects that it is easier to manipulate bit masks in hexadecimal rather than in decimal.

The scsi_level parameter is the ANSI SCSI standard level that the simulated disk announces that it is compliant to. This value should be 0 (no compliance claimed), 1 (SCSI-1),  2 (SCSI-2), 3 (SPC), 4 (SPC-2) or 5 (SPC-3). The default is 5. The INQUIRY response which is generated by scsi_ses contains the ANSI SCSI standard level value (in byte 2).

Supported SCSI commands
The supported commands are:

[ALLOW MEDIUM REMOVAL]
INQUIRY [vital product data pages: 0, 0x80, 0x83 (t10 vendor + naa(5) descriptors)]
MODE SENSE(6), MODE_SENSE(10) {sense pages: 1 (rw error recovery), 2 (disconnect), 3 (format), 8 (caching), 0xa (control), 0x1c (informational exceptions), 0x3f (read all)}
[READ (6), READ (10), READ(12), READ(16)]
[READ CAPACITY]
READ DIAGNOSTIC RESULTS
[RELEASE(6), RELEASE(10)]
REPORT LUNS
REQUEST SENSE
[RESERVE(6), RESERVE(10)]
[REZERO UNIT (which is REWIND for tapes)]
SEND DIAGNOSTIC
[START STOP]
[SYNCHRONIZE CACHE]
TEST UNIT READY
[VERIFY(10)]
[WRITE(6), WRITE(10), WRITE(12), WRITE(16)]
Those commands shown above in brackets are only supported when "ses_only=0" (i.e. when scsi_ses is simulating a disk). The implementations of the above commands are sufficient for the scsi subsystem to detect and attach devices. The fdisk, e2fsck and mount commands also work (when "ses_only=0") as do the utilities found in the sg3_utils package (see the main page). Crude error processing picks up unsupported commands and various other error conditions. <>Modern SCSI devices use vital product page 0x83 for identification. This driver yields both "T10 vendor identification" and "NAA" descriptors. The former yields an ASCII string like "Linux   scsi_ses        4000" where the "4000" is the ((host_no + 1) * 2000) + (target_id * 1000) + lun). In this case "4000" corresponds to host_no==1,  target_id==0 and lun==0. The "NAA" descriptor is an 8 byte binary value that looks like this hex sequence: "51 23 45 60 00 00 0f a0" where the IEEE company id is 0x123456 (fake) and the vendor specific identifier in the least significant bytes is 4000 (which is fa0 in hex). [The "4000" is derived the same way for both descriptors.]
Supported SES Diagnostic pages
A SES  (and SES-2 draft) application client communicates with a SES device via diagnostic pages. Status diagnostic pages are fetched from a SES device with the  RECEIVE DIAGNOSTIC RESULTS SCSI command. Control diagnostic pages are sent to a SES device with the SCSI SEND DIAGNOSTIC SCSI command. The supported status diagnostic pages are:
List supported diagnostic pages [0x0]
Configuration [0x1]
Enclosure status [0x2]
Help text [0x3]
String In [0x4]
Threshold In [0x5]
Element descriptor [0x7]
Enclosure busy [0x9]
The supported control diagnostic pages are:
Enclosure control [0x2]
String Out [0x4]
Threshold Out [0x5]
See the following usage section for some examples.
Usage
When the driver is loaded successfully simulated disks should be visible just like other SCSI devices: <>$ modprobe scsi_ses ses_only=1
$ cat /proc/scsi/scsi
Attached devices:
Host: scsi0 Channel: 00 Id: 00 Lun: 00
  Vendor: Linux    Model: scsi_ses         Rev: 0004
  Type:   Enclosure                        ANSI SCSI revision: 05
$ lsscsi -g
[0:0:0:0]    enclosu Linux    scsi_ses         0004  -         /dev/sg0

Notice that a simple (i.e. not disk attached) SES device must be accessed via the SCSI generic (sg) driver in linux. This is indicated by the "-" in the place the primary device node would be in the output from the lsscsi command. Here is similar output when a disk with attached enclosure services is simulated:
$ modprobe scsi_ses
$ cat /proc/scsi/scsi
Attached devices:
Host: scsi0 Channel: 00 Id: 00 Lun: 00
  Vendor: Linux    Model: scsi_ses         Rev: 0004
  Type:   Direct-Access                    ANSI SCSI revision: 05
$ lsscsi -g
[0:0:0:0]    disk    Linux    scsi_ses         0004  /dev/sda  /dev/sg0

$ sg_ses /dev/sda
  Linux     scsi_ses          0004
    disk device has EncServ bit set
Supported diagnostic pages:
  Supported diagnostic pages [0x0]
  Configuration (SES) [0x1]
  Enclosure status/control (SES) [0x2]
  Help text (SES) [0x3]
  String In/Out (SES) [0x4]
  Threshold In/Out (SES) [0x5]
  Element descriptor (SES) [0x7]
  Enclosure busy (SES-2) [0x9]

Now the sg_ses utility from the sg3_utils package is used to list the supported diagnostic pages (which is page 0x0 and the default page number of the sg_ses utility).

$ sg_ses -p 5 /dev/sg0
  Linux     scsi_ses          0004
    disk device has EncServ bit set
Threshold In diagnostic page:
  INVOP=0
  generation code: 0x0
    Element type: Power supply, subenclosure id: 0
    Element type: Cooling, subenclosure id: 0
    Element type: Temperature sense, subenclosure id: 0
    Overall threshold: high critical=65, high warning=55
      low warning=5, low critical=0 (in degrees Celsius)
      Element 1 threshold: high critical=65, high warning=55
        low warning=5, low critical=0 (in degrees Celsius)
      Element 2 threshold: high critical=65, high warning=55
        low warning=5, low critical=0 (in degrees Celsius)
Above is the "Threshold In" (status) diagnostic page. Note that element types that don't have thresholds (e.g. power supply and cooling) are stepped over.
$ sg_ses -p 5 -r /dev/sg0 > t
Now send the output of the Threshold In diagnostic page in raw (i.e. ASCII-hex) form to a file called "t".
$ cat t
        00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        55 4b 19 14 55 4b 19 14  55 4b 19 14
Send the raw form to stdout so we can see it. With your favourite editor change the last temperature ("14" hex which represents 0 degrees centigrade due to the 20 degree implicit offset) to 3 C.
$ cat t
        00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        55 4b 19 14 55 4b 19 14  55 4b 19 17

Outputing file "t" again so we cab see the change in the last byte.
$ sg_ses --control -p 5 -d - /dev/sg0 < t
  Linux     scsi_ses          0004
    disk device has EncServ bit set
Sending Threshold Out [0x5] page, with page length=60 bytes
The above line should send the Threshold Out diagnostic page which is a "control" page to the device with the change.
$ sg_ses -p 5 /dev/sg0
  Linux     scsi_ses          0004
    disk device has EncServ bit set
Threshold In diagnostic page:
  INVOP=0
  generation code: 0x0
    Element type: Power supply, subenclosure id: 0
    Element type: Cooling, subenclosure id: 0
    Element type: Temperature sense, subenclosure id: 0
    Overall threshold: high critical=65, high warning=55
      low warning=5, low critical=0 (in degrees Celsius)
      Element 1 threshold: high critical=65, high warning=55
        low warning=5, low critical=0 (in degrees Celsius)
      Element 2 threshold: high critical=65, high warning=55
        low warning=5, low critical=3 (in degrees Celsius)
Finally outputing the Threshold In page again now shows that the low crtical temperature of element 2 has changed to 3 C.

Downloads
This driver is not currently in the linux 2.6 series kernel source tree. It will be submitted for consideration (but may be too specialized). Below is a patch that should create two new files: scsi_ses.h and scsi_ses.c and modify two existing files: Makefile and Kconfig. These four files are found in the drivers/scsi directory in the kernel source. To apply this patch something like this should work: "cd /usr/src/linux; zcat /tmp/scsi_ses2611rc4.diff.gz | patch -p1 --dry-run ". If there are no complaints in the output then do it again without the "--dry-run" argument. Then build the kernel and answer the question about including the scsi_ses driver with "m" or "y".


Linux version
tarball/gzipped_patch
version
Notes
2.6.11-rc4
scsi_ses2611rc4.diff.gz
1.02
initial version
2.6.11
scsi_ses2611.diff.gz	1.02
minor change to Kconfig patch
2.6.12-rc4
scsi_ses2612rc4.diff.gz
1.02
resync
2.6.14-rc4
scsi_ses2614rc4.diff.gz	1.02
resync (works with lk 2.6.14)
2.6.15-rc5
scsi_ses2615rc5.diff.gz	1.03

2.6.17-rc1
scsi_ses2617rc1.diff.gz	1.04
tracking kernel changes, large transfers
2.6.19-rc2
scsi_ses2619rc2.diff.gz
1.05
mainly tracking kernel changes


Hopefully the design of the scsi_ses driver lends itself to such extensions. If you think that you have a useful extension that others may be interested in, contact one of the authors with a patch.


 Back  to main page

Douglas Gilbert (dgilbert at interlog dot com)
Zacharia Mathew (sakimathew at yahoo dot com)
Last updated: 24th October 2006
