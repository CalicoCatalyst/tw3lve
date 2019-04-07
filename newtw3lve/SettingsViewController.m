//
//  SettingController.m
//  izzatw3lve
//
//  Created by Tanay Findley on 3/31/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import "SettingsViewController.h"

@interface SettingsViewController ()
{
    IBOutlet UISwitch *restoreRootFS;
    IBOutlet UISegmentedControl *ExploitType;
    
    IBOutlet UISwitch *disableAppRevokes;
    IBOutlet UISwitch *disableAutoUpdates;
    IBOutlet UISwitch *loadTweaks;
}


@end

@implementation SettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self reloadData];
}

- (void)reloadData {
    [ExploitType setSelectedSegmentIndex:[[NSUserDefaults standardUserDefaults] integerForKey:EXPLOIT_TYPE]];
    [restoreRootFS setOn:[[NSUserDefaults standardUserDefaults] boolForKey:RESTORE_FS]];
    [loadTweaks setOn:[[NSUserDefaults standardUserDefaults] boolForKey:LOAD_TWEAKS]];
    [disableAutoUpdates setOn:[[NSUserDefaults standardUserDefaults] boolForKey:DISABLE_AUPDATES]];
    [disableAppRevokes setOn:[[NSUserDefaults standardUserDefaults] boolForKey:DAPP_REVOKES]];
    [self.tableView reloadData];
}

- (IBAction)exploitChanged:(id)sender {
    [[NSUserDefaults standardUserDefaults] setInteger:ExploitType.selectedSegmentIndex forKey:EXPLOIT_TYPE];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)restoreFSChanges:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[restoreRootFS isOn] forKey:RESTORE_FS];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}


- (IBAction)loadTweaksChanged:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[loadTweaks isOn] forKey:LOAD_TWEAKS];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}


- (IBAction)autoUpdatesChanged:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[disableAutoUpdates isOn] forKey:DISABLE_AUPDATES];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}


- (IBAction)appRevokeChanges:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[disableAppRevokes isOn] forKey:DAPP_REVOKES];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}



@end
