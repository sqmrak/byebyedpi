#ifndef BYE_PATHS_H
#define BYE_PATHS_H

/* /var/jb keeps the universal payload away from the sealed root filesystem */
#if defined(BYE_ROOTLESS)
#define BYE_JBROOT "/var/jb"
#else
#define BYE_JBROOT ""
#endif

#define BYE_USR_BIN BYE_JBROOT "/usr/bin"
#define BYE_USR_LIB BYE_JBROOT "/usr/lib"
#define BYE_LAUNCH_DAEMONS BYE_JBROOT "/Library/LaunchDaemons"

/* the roots the telegram gateway's certificate is checked against */
#define BYE_CA_BUNDLE BYE_USR_LIB "/byebyedpi/cacert.pem"

/* the host lists a config names with "hosts = NAME" are read from here. the
   app's user owns the directory, so the app can write the lists it composes */
#define BYE_HOSTS_DIR "/var/mobile/Library/Preferences/byebyedpi-hosts"
#define BYE_CONFIG_PATH "/var/root/Library/Preferences/byebyedpi.cfg"
#define BYE_CTL_SOCKET "/var/tmp/byedpid.sock"
/* /var/tmp is emptied at boot, and so are the routes it describes */
#define BYE_LEFTOVERS_PATH "/var/tmp/byedpid-utun-routes"
#define BYE_SYSTEM_LOG "/var/log/byebyedpi-system.log"

/* what the springboard hook reads, and the notification that wakes it */
#define BYE_STATUS_STATE "/var/mobile/Library/Preferences/com.byebyedpi.status.state"
#define BYE_STATUS_LOG "/var/mobile/Library/Preferences/com.byebyedpi.status.log"
#define BYE_STATUS_NOTIFY "com.byebyedpi.status.changed"

/* the mtu of the tunnel, and of the segments its tcp stack sends */
#define BYE_TUN_MTU 1500

#endif
