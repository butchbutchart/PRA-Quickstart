# PRA QuickStart Configuration Script



![image](https://github.com/user-attachments/assets/f289a6ae-7fbd-4d9e-8b47-c2e981c31039)

![image](https://github.com/user-attachments/assets/cab609c6-679a-4095-bb17-410ced20fa20)


## Features

### Created Objects
- **2 Jump Groups**: Site A and Site B with proper naming and comments
- **1 Team**: For user organization and management
- **3 Jump Policies**: 
  - Standard Business (business hours, basic security)
  - High Security (2FA required, notifications, strict controls)
  - Manager Access (extended permissions, 2FA required)
- **1 Jumpoint Cluster**: Windows-based cluster for connectivity
- **2 Group Policies**: 
  - Manager Users Policy (full permissions)
  - Standard Users Policy (restricted permissions)

### Automatic Relationship Setup
- **Manager Users Policy**:
  - Team membership with Manager role
  - Access to both Jump Groups with Standard Business policy
  - "Manage" Jump Item Role for full control
  - All session capabilities enabled
  - Jumpoint Cluster access

- **Standard Users Policy**:
  - Team membership with Member role
  - Jump Group A with Standard Business policy
  - Jump Group B with High Security policy
  - "Start Sessions Only" Jump Item Role
  - Limited session capabilities
  - Jumpoint Cluster access

## Prerequisites

1. **BeyondTrust API Account** with Configuration API permissions
2. **PowerShell 5.1+** (Windows PowerShell or PowerShell Core)
3. **Network Access** to your BeyondTrust appliance
4. **API Credentials** (Client ID and Secret)

## Files

- `PRA_Quickstart_Configuration.ps1` - Main script
- `pra-quickstart-config.txt` - Configuration file
- `bt-created-objects.json` - Auto-generated tracking file (for cleanup)

## Usage

### 1. Configure Settings
Edit `pra_QuickStart_config.txt` with your environment details:

```ini
# Update these with your actual values
tokenUrl=https://your-appliance.beyondtrustcloud.com/oauth2/token
baseUrl=https://your-appliance.beyondtrustcloud.com/api/config/v1
client_id=your_client_id_here
secret=your_secret_here

# Customize object names as needed
jumpgroupA_name=Production Site A
jumpgroupB_name=Production Site B
team_name=Operations Team
cluster_name=Main Jumpoint Cluster
```

### 2. Run the Script

#### Create Complete Environment
```powershell
# Use default config file (bt-complete-config.txt)
.\BeyondTrust-Complete-Configuration.ps1

# Use custom config file
.\BeyondTrust-Complete-Configuration.ps1 -ConfigFile "my-config.txt"
```

#### Cleanup All Objects
```powershell
# Remove all objects created by the script
.\BeyondTrust-Complete-Configuration.ps1 -Cleanup
```

## Configuration Options

### Jump Groups
- **jumpgroupA_name**: Display name for Jump Group A
- **jumpgroupA_codename**: Code name (alphanumeric, underscore, hyphen only)
- **jumpgroupA_comments**: Description/comments
- **jumpgroupB_name**: Display name for Jump Group B
- **jumpgroupB_codename**: Code name
- **jumpgroupB_comments**: Description/comments

### Team
- **team_name**: Display name for the team
- **team_code_name**: Code name
- **team_comments**: Description/comments

### Jumpoint Cluster
- **cluster_name**: Display name for the cluster
- **cluster_code_name**: Code name
- **cluster_comments**: Description/comments
- **cluster_enabled**: Enable/disable the cluster (true/false)
- **cluster_shell_jump_enabled**: Allow Shell Jump sessions (true/false)
- **cluster_protocol_tunnel_enabled**: Allow Protocol Tunnel sessions (true/false)
- **cluster_managed_ip_ranges**: IP ranges for network tunneling (format: start-end;start-end)

## Security Configuration

### Manager Users Policy
- **Full Access**: All session types enabled
- **Team Management**: Manager role in the team
- **Jump Group Access**: Full management rights to both Jump Groups
- **Session Control**: Can collaborate, share, and control sessions
- **No Timeout**: Session idle timeout disabled
- **External Access**: Can invite external users and manage keys

### Standard Users Policy
- **Limited Access**: Basic session types enabled
- **Team Member**: Member role in the team
- **Restricted Jump Access**: 
  - Jump Group A: Standard Business policy
  - Jump Group B: High Security policy (requires 2FA)
- **No Session Control**: Cannot collaborate or share with other teams
- **1 Hour Timeout**: Session idle timeout set to 1 hour
- **No External Access**: Cannot invite external users

### Jump Policies
- **Standard Business**: Business hours restriction, basic security
- **High Security**: 2FA required, notifications enabled, no simultaneous sessions
- **Manager Access**: Extended hours, 2FA required, flexible access

## Output and Logging

The script provides detailed output including:
- Authentication status
- Object creation results with IDs
- Relationship setup confirmation
- Summary of all created objects
- Error details if any operations fail

### Sample Output
```
============================================================
BEYONDTRUST COMPLETE CONFIGURATION
============================================================
Starting comprehensive BeyondTrust configuration...

✓ Authentication successful

============================================================
Creating Jump Groups
============================================================
✓ Creating Jump Group A: Site A
  Jump Group A ID: 123
✓ Creating Jump Group B: Site B
  Jump Group B ID: 124

============================================================
Creating Team
============================================================
✓ Creating Team: API Created Team
  Team ID: 45

[... continued output ...]

============================================================
CONFIGURATION SUMMARY
============================================================
✓ Configuration completed successfully!

Created Objects:
  Jump Groups: 2
    - Jump Group ID: 123
    - Jump Group ID: 124
  Team ID: 45
  Jump Policies: 3
    - Jump Policy ID: 67
    - Jump Policy ID: 68
    - Jump Policy ID: 69
  Jumpoint Cluster ID: 89
  Group Policies: 2
    - Group Policy ID: 101
    - Group Policy ID: 102
```

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify client_id and secret are correct
   - Check that the API account has Configuration API permissions
   - Ensure tokenUrl is correct

2. **Object Creation Failed**
   - Check for duplicate names if re-running
   - Verify the API account has sufficient permissions
   - Review error details in the output

3. **Relationship Setup Failed**
   - Ensure parent objects were created successfully
   - Check for proper ID references in tracking

### Cleanup Issues
If cleanup fails, you can manually remove objects in this order:
1. Group Policies
2. Jumpoint Cluster
3. Jump Policies
4. Team
5. Jump Groups

### Manual Verification
After running the script, verify the setup in the BeyondTrust console:
1. **Users & Security > Group Policies** - Check both policies exist
2. **Users & Security > Teams** - Verify team creation
3. **Access > Jump Groups** - Confirm both Jump Groups
4. **Access > Jump Policies** - Check all three policies
5. **Access > Jumpoints** - Verify cluster creation

## Next Steps

After running the script:

1. **Install Jumpoint Agents** using the Docker deploy key shown in output
2. **Create Jump Items** and assign them to the Jump Groups
3. **Add Users** to the appropriate Group Policies
4. **Test Access** with different user types to verify permissions
5. **Configure Schedules** for the Jump Policies if needed
6. **Set up Notifications** by configuring SMTP settings

## Advanced Customization

### Adding Custom Fields
You can extend the script by:
- Adding more Jump Groups in the config file
- Creating additional Jump Policies with different settings
- Customizing Group Policy permissions
- Adding more complex IP range configurations

### Integration with Other Scripts
This script can be integrated with:
- User provisioning scripts
- Jump Item creation scripts
- Monitoring and reporting scripts
- Backup and restore procedures

## Support and Maintenance

- **Tracking File**: `bt-created-objects.json` stores all created object IDs
- **Logging**: All operations are logged with success/failure status
- **Rollback**: Use the `-Cleanup` parameter for complete removal
- **Updates**: Modify the config file and re-run for environment changes

For additional help, consult the BeyondTrust API documentation or contact your BeyondTrust administrator.
