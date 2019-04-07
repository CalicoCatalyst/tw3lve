//
//  SettingController.h
//  izzatw3lve
//
//  Created by Tanay Findley on 3/31/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import <UIKit/UIKit.h>

#define EXPLOIT_TYPE         @"ExploitType"
#define RESTORE_FS           @"RestoreFS"
#define LOAD_TWEAKS          @"LoadTweaks"
#define DISABLE_AUPDATES     @"DAUPDATES"
#define DAPP_REVOKES         @"DAPP_REVOKES"

NS_ASSUME_NONNULL_BEGIN

@interface SettingsViewController : UITableViewController

@end

NS_ASSUME_NONNULL_END
