# BeyondTrust Privileged Remote Access - Complete Configuration Script
# This script creates a full environment including Jump Groups, Team, Jump Policies, 
# Jumpoint Cluster, and Group Policies with proper memberships

param(
    [switch]$Cleanup,
    [string]$ConfigFile = "pra-quickstart-config.txt"
)

# Get the directory where the script is located
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$configFile = Join-Path $scriptDir $ConfigFile

# Check if config file exists
if (-not (Test-Path $configFile)) {
    Write-Error "Config file '$ConfigFile' not found in script directory: $scriptDir"
    Write-Error "Please create the config file with the required settings."
    exit 1
}

# Read and parse config file
$config = @{}
Get-Content $configFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and $line -notmatch '^#') {
        $key, $value = $line -split '=', 2
        if ($key -and $value) {
            $config[$key.Trim()] = $value.Trim()
        }
    }
}

# Set connection variables from config
$tokenUrl = $config['tokenUrl']
$baseUrl = $config['baseUrl'] 
$client_id = $config['client_id']
$secret = $config['secret']

# Validate required config values
if (-not $tokenUrl -or -not $baseUrl -or -not $client_id -or -not $secret) {
    Write-Error "Missing required configuration values. Please check $ConfigFile file."
    Write-Error "Required: tokenUrl, baseUrl, client_id, secret"
    exit 1
}

#region Authentication 
Write-Output "Authenticating with BeyondTrust API..."
$credPair = "$($client_id):$($secret)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$headersCred = @{ Authorization = "Basic $encodedCredentials" }

try {
    $responsetoken = Invoke-RestMethod -Uri "$tokenUrl" -Method Post -Body "grant_type=client_credentials" -Headers $headersCred
    $token = $responsetoken.access_token
    
    $headers = @{
        "Content-Type" = "application/json"
        "Accept" = "application/json"
        "Authorization" = "Bearer $token"
    }
    Write-Output "✓ Authentication successful"
} catch {
    Write-Error "✗ Authentication failed: $_"
    exit 1
}
#endregion

# Storage for created object IDs (for cleanup)
$createdObjects = @{
    JumpGroups = @()
    Team = $null
    JumpPolicies = @()
    JumpointCluster = $null
    GroupPolicies = @()
}

#region Helper Functions
function Convert-ConfigValue {
    param($value)
    if ($value -eq "true") { return $true }
    if ($value -eq "false") { return $false }
    if ($value -match '^\d+$') { return [int]$value }
    return $value
}

function Parse-ArrayConfig {
    param($value)
    if ([string]::IsNullOrEmpty($value)) { return @() }
    return @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Write-Section {
    param([string]$Title)
    Write-Output ""
    Write-Output "=" * 60
    Write-Output $Title
    Write-Output "=" * 60
}

function Invoke-BTApiCall {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [object]$Body = $null,
        [string]$Description
    )
    
    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            Headers = $headers
        }
        
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
        }
        
        $response = Invoke-RestMethod @params
        if ($Description) {
            Write-Output "✓ $Description"
        }
        return $response
    } catch {
        if ($Description) {
            Write-Error "✗ Failed: $Description - $_"
        } else {
            Write-Error "✗ API call failed: $_"
        }
        
        if ($_.Exception.Response) {
            try {
                $responseBody = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($responseBody)
                $responseText = $reader.ReadToEnd()
                Write-Error "Response details: $responseText"
            } catch {}
        }
        return $null
    }
}
#endregion

#region Cleanup Function
function Remove-CreatedObjects {
    Write-Section "CLEANUP - Removing All Created Objects"
    
    # Remove Group Policies
    foreach ($policyId in $createdObjects.GroupPolicies) {
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$policyId" -Method DELETE -Description "Removing Group Policy ID: $policyId"
    }
    
    # Remove Jumpoint Cluster
    if ($createdObjects.JumpointCluster) {
        $result = Invoke-BTApiCall -Uri "$baseUrl/jumpoint/$($createdObjects.JumpointCluster)" -Method DELETE -Description "Removing Jumpoint Cluster ID: $($createdObjects.JumpointCluster)"
    }
    
    # Remove Jump Policies
    foreach ($policyId in $createdObjects.JumpPolicies) {
        $result = Invoke-BTApiCall -Uri "$baseUrl/jump-policy/$policyId" -Method DELETE -Description "Removing Jump Policy ID: $policyId"
    }
    
    # Remove Team
    if ($createdObjects.Team) {
        $result = Invoke-BTApiCall -Uri "$baseUrl/team/$($createdObjects.Team)" -Method DELETE -Description "Removing Team ID: $($createdObjects.Team)"
    }
    
    # Remove Jump Groups
    foreach ($groupId in $createdObjects.JumpGroups) {
        $result = Invoke-BTApiCall -Uri "$baseUrl/jump-group/$groupId" -Method DELETE -Description "Removing Jump Group ID: $groupId"
    }
    
    Write-Output ""
    Write-Output "Cleanup completed."
    return
}
#endregion

# Handle cleanup mode
if ($Cleanup) {
    Write-Output "Starting cleanup process..."
    
    # Try to load previously created object IDs from a tracking file
    $trackingFile = Join-Path $scriptDir "bt-created-objects.json"
    if (Test-Path $trackingFile) {
        try {
            Write-Output "Found tracking file: $trackingFile"
            $trackingContent = Get-Content $trackingFile -Raw
            Write-Output "Tracking file content loaded successfully"
            
            # Convert from JSON with compatibility for older PowerShell versions
            $trackingData = $trackingContent | ConvertFrom-Json
            
            # Convert to hashtable manually for compatibility
            $createdObjects = @{
                JumpGroups = @()
                Team = $null
                JumpPolicies = @()
                JumpointCluster = $null
                GroupPolicies = @()
            }
            
            if ($trackingData.JumpGroups) {
                $createdObjects.JumpGroups = @($trackingData.JumpGroups)
            }
            if ($trackingData.Team) {
                $createdObjects.Team = $trackingData.Team
            }
            if ($trackingData.JumpPolicies) {
                $createdObjects.JumpPolicies = @($trackingData.JumpPolicies)
            }
            if ($trackingData.JumpointCluster) {
                $createdObjects.JumpointCluster = $trackingData.JumpointCluster
            }
            if ($trackingData.GroupPolicies) {
                $createdObjects.GroupPolicies = @($trackingData.GroupPolicies)
            }
            
            Write-Output "Successfully loaded object tracking information:"
            Write-Output "  Group Policies: $($createdObjects.GroupPolicies -join ', ')"
            Write-Output "  Jumpoint Cluster: $($createdObjects.JumpointCluster)"
            Write-Output "  Jump Policies: $($createdObjects.JumpPolicies -join ', ')"
            Write-Output "  Team: $($createdObjects.Team)"
            Write-Output "  Jump Groups: $($createdObjects.JumpGroups -join ', ')"
            
        } catch {
            Write-Error "Could not load tracking file: $_"
            Write-Output "Tracking file content preview:"
            Get-Content $trackingFile | Select-Object -First 10 | ForEach-Object { Write-Output "  $_" }
            Write-Warning "Manual cleanup may be required."
            return
        }
    } else {
        Write-Warning "No tracking file found at: $trackingFile"
        Write-Warning "You may need to manually identify and remove objects."
        return
    }
    
    Remove-CreatedObjects
    
    # Remove tracking file after cleanup
    if (Test-Path $trackingFile) {
        Remove-Item $trackingFile -Force
        Write-Output "Removed tracking file: $trackingFile"
    }
    
    exit 0
}

#region Main Configuration Process

Write-Section "BEYONDTRUST COMPLETE CONFIGURATION"
Write-Output "Starting comprehensive BeyondTrust configuration..."

#region Get Jump Item Role IDs
Write-Section "Getting Jump Item Role Configuration"

# Get Jump Item Role IDs from config
$manageRoleId = $null
$startOnlyRoleId = $null

if ($config['management_role_id'] -and $config['management_role_id'] -match '^\d+$') {
    $manageRoleId = [int]$config['management_role_id']
    Write-Output "Using configured Management Role ID: $manageRoleId"
} else {
    Write-Error "management_role_id is required in the config file. Please add: management_role_id=X"
    exit 1
}

if ($config['start_sessions_role_id'] -and $config['start_sessions_role_id'] -match '^\d+$') {
    $startOnlyRoleId = [int]$config['start_sessions_role_id']
    Write-Output "Using configured Start Sessions Role ID: $startOnlyRoleId"
} else {
    Write-Error "start_sessions_role_id is required in the config file. Please add: start_sessions_role_id=Y"
    exit 1
}

Write-Output ""
Write-Output "Jump Item Roles Configuration:"
Write-Output "  Management Role ID: $manageRoleId"
Write-Output "  Start Sessions Role ID: $startOnlyRoleId"
#endregion

#region Create Jump Groups
Write-Section "Creating Jump Groups"

# Jump Group A
$jumpGroupA_Name = $config['jumpgroupA_name']
$jumpGroupA_CodeName = $config['jumpgroupA_codename']
$jumpGroupA_Comments = $config['jumpgroupA_comments']

if ($jumpGroupA_Name) {
    $jumpGroupA_Body = @{ "name" = $jumpGroupA_Name }
    if ($jumpGroupA_CodeName -and $jumpGroupA_CodeName -match '^[a-zA-Z0-9_\-]+$') {
        $jumpGroupA_Body["code_name"] = $jumpGroupA_CodeName
    }
    if ($jumpGroupA_Comments) {
        $jumpGroupA_Body["comments"] = $jumpGroupA_Comments
    }
    
    $jumpGroupA = Invoke-BTApiCall -Uri "$baseUrl/jump-group" -Method POST -Body $jumpGroupA_Body -Description "Creating Jump Group A: $jumpGroupA_Name"
    
    if ($jumpGroupA) {
        $createdObjects.JumpGroups += $jumpGroupA.id
        Write-Output "  Jump Group A ID: $($jumpGroupA.id)"
    }
}

# Jump Group B
$jumpGroupB_Name = $config['jumpgroupB_name']
$jumpGroupB_CodeName = $config['jumpgroupB_codename'] 
$jumpGroupB_Comments = $config['jumpgroupB_comments']

if ($jumpGroupB_Name) {
    $jumpGroupB_Body = @{ "name" = $jumpGroupB_Name }
    if ($jumpGroupB_CodeName -and $jumpGroupB_CodeName -match '^[a-zA-Z0-9_\-]+$') {
        $jumpGroupB_Body["code_name"] = $jumpGroupB_CodeName
    }
    if ($jumpGroupB_Comments) {
        $jumpGroupB_Body["comments"] = $jumpGroupB_Comments
    }
    
    $jumpGroupB = Invoke-BTApiCall -Uri "$baseUrl/jump-group" -Method POST -Body $jumpGroupB_Body -Description "Creating Jump Group B: $jumpGroupB_Name"
    
    if ($jumpGroupB) {
        $createdObjects.JumpGroups += $jumpGroupB.id
        Write-Output "  Jump Group B ID: $($jumpGroupB.id)"
    }
}
#endregion

#region Create Team
Write-Section "Creating Team"

$team_Name = $config['team_name']
if ($team_Name) {
    $team_Body = @{ "name" = $team_Name }
    
    if ($config['team_code_name'] -and $config['team_code_name'] -match '^[a-zA-Z0-9_\-]+$') {
        $team_Body["code_name"] = $config['team_code_name']
    }
    if ($config['team_comments']) {
        $team_Body["comments"] = $config['team_comments']
    }
    
    $team = Invoke-BTApiCall -Uri "$baseUrl/team" -Method POST -Body $team_Body -Description "Creating Team: $team_Name"
    
    if ($team) {
        $createdObjects.Team = $team.id
        Write-Output "  Team ID: $($team.id)"
    }
}
#endregion

#region Create Jump Policies
Write-Section "Creating Jump Policies"

# Standard Business Policy
$policy1_Body = @{
    "display_name" = "Standard Business"
    "code_name" = "standard_business"
    "description" = "Standard business hours access policy"
    "schedule_enabled" = $true
    "simultaneous_jumps" = "join"
    "ticket_id_required" = $false
    "two_factor_challenge_required" = $false
    "session_start_notification" = $false
    "session_end_notification" = $false
    "approval_required" = $false
    "recordings_disabled" = $false
}

$policy1 = Invoke-BTApiCall -Uri "$baseUrl/jump-policy" -Method POST -Body $policy1_Body -Description "Creating Jump Policy: Standard Business"

if ($policy1) {
    $createdObjects.JumpPolicies += $policy1.id
    Write-Output "  Standard Business Policy ID: $($policy1.id)"
}

# High Security Policy
$policy2_Body = @{
    "display_name" = "High Security"
    "code_name" = "high_security"
    "description" = "High security access policy with strict controls"
    "schedule_enabled" = $true
    "simultaneous_jumps" = "disallow"
    "ticket_id_required" = $true
    "two_factor_challenge_required" = $true
    "session_start_notification" = $true
    "session_end_notification" = $true
    "approval_required" = $false
    "recordings_disabled" = $false
    "notification_email_addresses" = @("admin@company.com")
    "notification_display_name" = "Security Team"
    "notification_email_language" = "en-us"
}

$policy2 = Invoke-BTApiCall -Uri "$baseUrl/jump-policy" -Method POST -Body $policy2_Body -Description "Creating Jump Policy: High Security"

if ($policy2) {
    $createdObjects.JumpPolicies += $policy2.id
    Write-Output "  High Security Policy ID: $($policy2.id)"
}

# Manager Policy
$policy3_Body = @{
    "display_name" = "Manager Access"
    "code_name" = "manager_access"
    "description" = "Manager level access policy with extended permissions"
    "schedule_enabled" = $false
    "simultaneous_jumps" = "join"
    "ticket_id_required" = $false
    "two_factor_challenge_required" = $true
    "session_start_notification" = $false
    "session_end_notification" = $false
    "approval_required" = $false
    "recordings_disabled" = $false
}

$policy3 = Invoke-BTApiCall -Uri "$baseUrl/jump-policy" -Method POST -Body $policy3_Body -Description "Creating Jump Policy: Manager Access"

if ($policy3) {
    $createdObjects.JumpPolicies += $policy3.id
    Write-Output "  Manager Access Policy ID: $($policy3.id)"
}
#endregion

#region Create Jumpoint Cluster
Write-Section "Creating Jumpoint Cluster"

$cluster_name = $config['cluster_name']
if ($cluster_name) {
    $cluster_Body = @{
        "name" = $cluster_name
        "platform" = "windows-x86"
        "clustered" = $true
        "enabled" = Convert-ConfigValue $config['cluster_enabled']
        "shell_jump_enabled" = Convert-ConfigValue $config['cluster_shell_jump_enabled']
        "protocol_tunnel_enabled" = Convert-ConfigValue $config['cluster_protocol_tunnel_enabled']
    }
    
    # Add optional fields
    if ($config['cluster_code_name']) {
        $cluster_Body["code_name"] = $config['cluster_code_name']
    }
    if ($config['cluster_comments']) {
        $cluster_Body["comments"] = $config['cluster_comments']
    }
    
    # Handle IP ranges if specified
    if ($config['cluster_managed_ip_ranges']) {
        $ranges = @()
        $rangeStrings = $config['cluster_managed_ip_ranges'] -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        
        foreach ($rangeString in $rangeStrings) {
            if ($rangeString -match '([0-9.]+)-([0-9.]+)') {
                $ranges += @{
                    "start" = $matches[1]
                    "end" = $matches[2]
                }
            }
        }
        
        if ($ranges.Count -gt 0) {
            $cluster_Body["managed_ip_ranges"] = $ranges
        }
    }
    
    $cluster = Invoke-BTApiCall -Uri "$baseUrl/jumpoint" -Method POST -Body $cluster_Body -Description "Creating Jumpoint Cluster: $cluster_name"
    
    if ($cluster) {
        $createdObjects.JumpointCluster = $cluster.id
        Write-Output "  Jumpoint Cluster ID: $($cluster.id)"
        if ($cluster.docker_deploy_key) {
            Write-Output "  Docker Deploy Key: $($cluster.docker_deploy_key)"
        }
    }
}
#endregion

#region Create Group Policies
Write-Section "Creating Group Policies"

# Manager Users Group Policy
$managerPolicy_Body = @{
    "name" = "Manager Users Policy"
    "perm_access_allowed" = $true
    "access_perm_status" = "defined"
    "perm_jump_client" = $true
    "perm_remote_jump" = $true
    "perm_remote_vnc" = $true
    "perm_remote_rdp" = $true
    "perm_shell_jump" = $true
    "perm_web_jump" = $true
    "perm_protocol_tunnel" = $true
    "perm_collaborate" = $true
    "perm_collaborate_control" = $true
    "perm_share_other_team" = $true
    "perm_invite_external_user" = $true
    "perm_extended_availability_mode_allowed" = $true
    "perm_edit_external_key" = $true
    "perm_sd_static_port_for_external_tools" = $true
    "perm_session_idle_timeout" = 0
    "default_jump_item_role_id" = $manageRoleId
    "private_jump_item_role_id" = $manageRoleId
    "inferior_jump_item_role_id" = $manageRoleId
    "unassigned_jump_item_role_id" = $manageRoleId
}

$managerPolicy = Invoke-BTApiCall -Uri "$baseUrl/group-policy" -Method POST -Body $managerPolicy_Body -Description "Creating Manager Users Group Policy"

if ($managerPolicy) {
    $createdObjects.GroupPolicies += $managerPolicy.id
    Write-Output "  Manager Users Policy ID: $($managerPolicy.id)"
    
    # Add Jumpoint membership
    if ($createdObjects.JumpointCluster) {
        $jumpointMembership = @{ "jumpoint_id" = $createdObjects.JumpointCluster }
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$($managerPolicy.id)/jumpoint" -Method POST -Body $jumpointMembership -Description "Adding Jumpoint to Manager Policy"
    }
    
    # Add Team membership with Manager role
    if ($createdObjects.Team) {
        $teamMembership = @{
            "team_id" = $createdObjects.Team
            "role" = "manager"
        }
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$($managerPolicy.id)/team" -Method POST -Body $teamMembership -Description "Adding Team membership (Manager role) to Manager Policy"
    }
    
    # Add Jump Group memberships
    if ($jumpGroupA -and $policy1) {
        $jumpGroupMembership = @{
            "jump_group_id" = $jumpGroupA.id
            "jump_item_role_id" = $manageRoleId
            "jump_policy_id" = $policy1.id
        }
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$($managerPolicy.id)/jump-group" -Method POST -Body $jumpGroupMembership -Description "Adding Jump Group A to Manager Policy"
    }
    
    if ($jumpGroupB -and $policy1) {
        $jumpGroupMembership = @{
            "jump_group_id" = $jumpGroupB.id
            "jump_item_role_id" = $manageRoleId
            "jump_policy_id" = $policy1.id
        }
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$($managerPolicy.id)/jump-group" -Method POST -Body $jumpGroupMembership -Description "Adding Jump Group B to Manager Policy"
    }
}

# Standard Users Group Policy
$standardPolicy_Body = @{
    "name" = "Standard Users Policy"
    "perm_access_allowed" = $true
    "access_perm_status" = "defined"
    "perm_jump_client" = $true
    "perm_remote_jump" = $true
    "perm_remote_vnc" = $true
    "perm_remote_rdp" = $true
    "perm_shell_jump" = $true
    "perm_web_jump" = $true
    "perm_protocol_tunnel" = $true
    "perm_collaborate" = $false
    "perm_collaborate_control" = $false
    "perm_share_other_team" = $false
    "perm_invite_external_user" = $false
    "perm_extended_availability_mode_allowed" = $false
    "perm_edit_external_key" = $false
    "perm_sd_static_port_for_external_tools" = $false
    "perm_session_idle_timeout" = 3600
    "default_jump_item_role_id" = $startOnlyRoleId
    "private_jump_item_role_id" = $startOnlyRoleId
    "inferior_jump_item_role_id" = $startOnlyRoleId
    "unassigned_jump_item_role_id" = $startOnlyRoleId
}

$standardPolicy = Invoke-BTApiCall -Uri "$baseUrl/group-policy" -Method POST -Body $standardPolicy_Body -Description "Creating Standard Users Group Policy"

if ($standardPolicy) {
    $createdObjects.GroupPolicies += $standardPolicy.id
    Write-Output "  Standard Users Policy ID: $($standardPolicy.id)"
    
    # Add Jumpoint membership
    if ($createdObjects.JumpointCluster) {
        $jumpointMembership = @{ "jumpoint_id" = $createdObjects.JumpointCluster }
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$($standardPolicy.id)/jumpoint" -Method POST -Body $jumpointMembership -Description "Adding Jumpoint to Standard Policy"
    }
    
    # Add Team membership with Member role
    if ($createdObjects.Team) {
        $teamMembership = @{
            "team_id" = $createdObjects.Team
            "role" = "member"
        }
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$($standardPolicy.id)/team" -Method POST -Body $teamMembership -Description "Adding Team membership (Member role) to Standard Policy"
    }
    
    # Add Jump Group A with Standard Business policy
    if ($jumpGroupA -and $policy1) {
        $jumpGroupMembership = @{
            "jump_group_id" = $jumpGroupA.id
            "jump_item_role_id" = $startOnlyRoleId
            "jump_policy_id" = $policy1.id
        }
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$($standardPolicy.id)/jump-group" -Method POST -Body $jumpGroupMembership -Description "Adding Jump Group A (Standard Business) to Standard Policy"
    }
    
    # Add Jump Group B with High Security policy
    if ($jumpGroupB -and $policy2) {
        $jumpGroupMembership = @{
            "jump_group_id" = $jumpGroupB.id
            "jump_item_role_id" = $startOnlyRoleId
            "jump_policy_id" = $policy2.id
        }
        $result = Invoke-BTApiCall -Uri "$baseUrl/group-policy/$($standardPolicy.id)/jump-group" -Method POST -Body $jumpGroupMembership -Description "Adding Jump Group B (High Security) to Standard Policy"
    }
}
#endregion

#region Save Tracking Information
# Save created object IDs for cleanup purposes
$trackingFile = Join-Path $scriptDir "bt-created-objects.json"
try {
    $createdObjects | ConvertTo-Json -Depth 3 | Set-Content $trackingFile
    Write-Output ""
    Write-Output "Object tracking information saved to: $trackingFile"
    Write-Output "Use -Cleanup parameter to remove all created objects."
} catch {
    Write-Warning "Could not save tracking information: $_"
}
#endregion

#region Summary
Write-Section "CONFIGURATION SUMMARY"

Write-Output "✓ Configuration completed successfully!"
Write-Output ""
Write-Output "Created Objects:"
Write-Output "  Jump Groups: $($createdObjects.JumpGroups.Count)"
foreach ($id in $createdObjects.JumpGroups) {
    Write-Output "    - Jump Group ID: $id"
}

if ($createdObjects.Team) {
    Write-Output "  Team ID: $($createdObjects.Team)"
}

Write-Output "  Jump Policies: $($createdObjects.JumpPolicies.Count)"
foreach ($id in $createdObjects.JumpPolicies) {
    Write-Output "    - Jump Policy ID: $id"
}

if ($createdObjects.JumpointCluster) {
    Write-Output "  Jumpoint Cluster ID: $($createdObjects.JumpointCluster)"
}

Write-Output "  Group Policies: $($createdObjects.GroupPolicies.Count)"
foreach ($id in $createdObjects.GroupPolicies) {
    Write-Output "    - Group Policy ID: $id"
}

Write-Output ""
Write-Output "Next Steps:"
Write-Output "1. Configure users and assign them to the appropriate Group Policies"
Write-Output "2. Install Jumpoint agents using the cluster deployment key"
Write-Output "3. Create Jump Items and assign them to the Jump Groups"
Write-Output "4. Test access with different user types"
Write-Output ""
Write-Output "To remove all created objects, run:"
Write-Output "  .\PRA_Quickstart_Configuration.ps1 -Cleanup"

#endregion

Write-Output ""
Write-Output "Configuration process completed successfully!"