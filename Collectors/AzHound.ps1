# Title: AzHound
# Author: Marius Elmiger (@m8r1us)
# File: AzHound.ps1
# Version: 0.4
# Description: Exports data from an Azure AD Tenant to JSON files.
#
# To retrieve the required data the following rights should be assigned to the users that runs the script:
# -> ARM Reader Role
# -> Azure AD Global Reader
# -> Approved PrivilegedAccess.Read.AzureAD App Role
# -> Approved PrivilegedAccess.Read.AzureADGroup App Role
# -> Approved PrivilegedAccess.Read.AzureResources App Role
#
# To import the data read the import-readme.md under the /import folder
#
# This version is based on the AzureHound.ps1 Version from SpecterOps
# Authors: Andy Robbins (@_wald0), Rohan Vazarkar (@cptjesus), Ryan Hausknecht (@haus3c)

Function get-authtoken ($resourceURI, $authority, $clientId) {
    #Parameters
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    #pre requisites
    try {
    $AadModule = Import-Module -Name AzureAD -ErrorAction Stop -PassThru
    }
    catch {
    throw 'Prerequisites not installed (AzureAD PowerShell module not installed)'
    }
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # Get token by prompting login window.
    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always"
    $authResult = $authContext.AcquireTokenAsync($resourceURI, $ClientID, $RedirectUri, $platformParameters)

    # Use the access token to setup headers for your http request.
    $authHeader = $authResult.Result.AccessTokenType + " " + $authResult.Result.AccessToken
    $headers = @{"Authorization"=$authHeader}

    return $headers
}

function Get-AzureGraphToken
{
    $msgraphtoken = Get-AzAccessToken -ResourceTypeName MSGraph
    $Headers = @{}
    $Headers.Add("Authorization","Bearer"+ " " + "$($msgraphtoken.Token)")
    $Headers

    <#
    $APSUser = Get-AzContext *>&1 
    $resource = "https://graph.microsoft.com"
    $Token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($APSUser.Account, $APSUser.Environment, $APSUser.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $resource).AccessToken
    $Headers = @{}
    $Headers.Add("Authorization","Bearer"+ " " + "$($token)")
    $Headers
    #>
}

$Verbose = $True
function Write-Info ($Message) {
    If ($Verbose) {
        Write-Host $Message
    }
}

function New-Output($Coll, $Type, $Directory) {

    $Count = $Coll.Count

    Write-Host "Writing output for $($Type)"
	if ($null -eq $Coll) {
        $Coll = New-Object System.Collections.ArrayList
    }

    # ConvertTo-Json consumes too much memory on larger objects, which can have millions
    # of entries in a large tenant. Write out the JSON structure a bit at a time to work
    # around this. This is a bit inefficient, but makes this work when the tenant becomes
    # too large.
    #$FileName = $Directory + [IO.Path]::DirectorySeparatorChar + $date + "-" + "az" + $($Type) + ".json"
    $FileName = $Directory + [IO.Path]::DirectorySeparatorChar + "az" + $($Type) + ".json"
    try {
        $Stream = [System.IO.StreamWriter]::new($FileName)

        # Write file header JSON
        $Stream.WriteLine('{')
        $Stream.WriteLine("`t""meta"": {")
        $Stream.WriteLine("`t`t""count"": $Count,")
        $Stream.WriteLine("`t`t""type"": ""az$($Type)"",")
        $Stream.WriteLine("`t`t""version"": 4")
        $Stream.WriteLine("`t},")        

        # Write data JSON
        $Stream.WriteLine("`t""data"": [")
        $Stream.Flush()

        $chunksize = 250
        $chunkarray = @()
        $parts = [math]::Ceiling($coll.Count / $chunksize)

        Write-Info "Chunking output in $chunksize item sections"
        for($n=0; $n -lt $parts; $n++){
            $start = $n * $chunksize
            $end = (($n+1)*$chunksize)-1
            $chunkarray += ,@($coll[$start..$end])
        }
        $Count = $chunkarray.Count

        $chunkcounter = 1
        $jsonout = ""
        ForEach ($chunk in $chunkarray) {
            Write-Info "Writing JSON chunk $chunkcounter/$Count"
            $jsonout = ConvertTo-Json($chunk)
            $jsonout = $jsonout.trimstart("[`r`n").trimend("`r`n]")
            $Stream.Write($jsonout)
            If ($chunkcounter -lt $Count) {
                $Stream.WriteLine(",")
            } Else {
                $Stream.WriteLine("")
            }
            $Stream.Flush()
            $chunkcounter += 1
        }
        $Stream.WriteLine("`t]")
        $Stream.WriteLine("}")
    } finally {
        $Stream.close()
    }
}

function Invoke-AzHound {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)][String]$Tenant = $null,
    [Parameter(Mandatory=$False)][String]$OutputDirectory = $(Get-Location),[ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$False)][Switch]$Install = $null)

    # ------------------------------------------------------------------------------------------------------------------------------
    # Powershell Module Installation
    # ------------------------------------------------------------------------------------------------------------------------------
    if ($Install){
      Install-Module -Name Az -AllowClobber
      Install-module -Name AzureADPreview -AllowClobber
    }

    $Modules = Get-InstalledModule
    if ($Modules.Name -notcontains 'Az.Accounts' -and $Modules.Name -notcontains 'AzureAD'){ 
      Write-Host "AzureHound requires the 'Az' and 'Azure AD PowerShell module, please install by using the -Install switch."
      exit
    }

    # ------------------------------------------------------------------------------------------------------------------------------
    # Azure AD Login
    # ------------------------------------------------------------------------------------------------------------------------------

    $date = get-date -f yyyyMMddhhmmss

    # Create token for Az
    # Check to see if we're logged in with Az
    Write-Host "Login to Azure AZ..."
    $LoginStatus = Get-AzContext
    if ($null -eq $LoginStatus.Account){
        Write-Host "No active AZ login. Prompting for login." 
        try {
                if ($Tenant)
                {
                    Connect-AzAccount -TenantId $Tenant -ErrorAction Stop | Out-Null
                }
                else
                {
                    Connect-AzAccount -ErrorAction Stop | Out-Null
                }
                $LoginStatus = Get-AzContext;
            }
        catch{
            Write-Host "Login process failed." -ForegroundColor Red;break
        }
    }
    else
    {
        $LoginStatus = Get-AzContext; $AZAccount = $LoginStatus.Account;
        Write-Verbose "Currently logged in via Az as $AZAccount"; 
        Write-Verbose 'Use Login-AzAccount to change your user'
    }

    # Connect to AzureAD with Az Token
    try 
    {
        Connect-AzureAD -TenantId $LoginStatus.Tenant.Id -AccountId $LoginStatus.Account.Id | Out-Null
    }
    catch{
        Connect-AzureAD
    }

    # Token for Microsoft Graph
    $apiRootAzureAD = "https://graph.microsoft.com/beta"
    $Headers = get-authtoken "https://graph.microsoft.com" "https://login.microsoftonline.com/common" "1b730954-1685-4b74-9bfd-dac224a7b894"
    #$Headers = Get-AzureGraphToken
    #$Headers = get-authtoken "https://graph.microsoft.com" "https://login.microsoftonline.com/common" "1950a258-227b-4e31-a9cf-717495945fc2"
    #$Headers = get-authtoken "https://graph.microsoft.com" "https://login.microsoftonline.com/common" "de8bc8b5-d9f9-48b1-a8ad-b748da725064"

    # ------------------------------------------------------------------------------------------------------------------------------
    # Variable Declarations
    # ------------------------------------------------------------------------------------------------------------------------------

    $script:ObjectByObjectId = @{}
    $script:ObjectByObjectClassId = @{}

    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate tenant
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    Write-Info "Building tenant(s) object."
    $AadTenant = Get-AzureADTenantDetail -All 1 | Select-Object ObjectId,DisplayName,VerifiedDomains,AssignedPlans
    $TotalCount = @($AadTenant).Count
    If ($TotalCount -gt 1) {
        Write-Info "Done building tenant object, processing ${TotalCount} tenant"
    } else {
        Write-Info "Done building tenants object, processing ${TotalCount} tenants"
    }
    $Progress = 0

    $DisplayName = $AadTenant.DisplayName
    $tenantId = $AadTenant.ObjectId.ToLower()

    $Progress += 1
    $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

    If ($Progress -eq $TotalCount) {
        Write-Info "Processing tenants: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current tenant: ${DisplayName}"
    } else {
        If (($Progress % 100) -eq 0) {
            Write-Info "Processing tenants: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current tenant: ${DisplayName}"
        } 
    }

    $Current = [PSCustomObject]@{
        objectid                       = $tenantId
        displayname                    = $AadTenant.DisplayName
        tenantId                       = $tenantId
        verifiedDomains                = $AadTenant.VerifiedDomains
        assignedPlans                  = $AadTenant.AssignedPlans.Service | Sort-Object | Get-Unique
    }

    $null = $Coll.Add($Current)

    New-Output -Coll $Coll -Type "tenant" -Directory $OutputDirectory

    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate Azure AD users
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    Write-Info "Building users object, this may take a few minutes."
	$AADUsers = Get-AzureADUser -All 1 | Select-Object ObjectType,UserPrincipalName,OnPremisesSecurityIdentifier,ObjectID,TenantId,email,AccountEnabled,ImmutableId,JobTitle,Mobile,ProxyAddresses,UserType
    $TotalCount = $AADUsers.Count
    Write-Host "Done building users object, processing ${TotalCount} users"
    $Progress = 0
    $AADUsers | ForEach-Object {

        $User = $_
        $DisplayName = ($User.UserPrincipalName).Split('@')[0]

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Host "Processing users: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user: ${DisplayName}"
        } else {
            If (($Progress % 1000) -eq 0) {
                Write-Host "Processing users: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user: ${DisplayName}"
            } 
        }

        $CurrentUserTenantID = $null
        If ($User.UserPrincipalName -NotMatch "#EXT#") {
            $CurrentUserTenantID = $tenantId
        }

        $CurrentUser = [PSCustomObject]@{
            displayname                     = $DisplayName
            userPrincipalName               = $User.UserPrincipalName
            onPremisesSecurityIdentifier    = $User.OnPremisesSecurityIdentifier
            email                           = $User.Mail
            objectid                        = $User.ObjectID
            tenantId                        = $CurrentUserTenantID
            enabled                         = $User.AccountEnabled
            immutableId                     = $User.ImmutableId
            jobTitle                        = $User.JobTitle
            mobile                          = $User.Mobile
            proxyAddresses                  = $User.ProxyAddresses
            userType                        = $User.UserType
        }
        
        $null = $Coll.Add($CurrentUser)
    }
    New-Output -Coll $Coll -Type "users" -Directory $OutputDirectory

    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate groups (Without Role Groups)
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    Write-Info "Building groups object, this may take a few minutes."

    # $AADGroups = Get-AzureADGroup -All $True -Filter "securityEnabled eq true"
    $aadRawGroups = Get-AzADGroup
    # $apiUrl = $apiRootAzureAD + "/groups?$select=id,displayName,OnPremisesSecurityIdentifier,organizationId,mail,securityEnabled,securityIdentifier,description,proxyAddresses,createdDateTime,onPremisesDomainName,isAssignableToRole,groupTypes"
    # $Data = Invoke-RestMethod -Headers $Headers -Uri $apiUrl -Method Get
    # $aadRawGroups = ($Data | select-object Value).Value
    # graph query cannot filter out NULL therefore we recreate the array without Role Groups
    $AADGroups = $aadRawGroups | Where-Object {$_.IsAssignableToRole -ne "True"}

    $TotalCount = $AADGroups.Count

    Write-Info "Done building groups object, processing ${TotalCount} groups"
    $Progress = 0
    $AADGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.displayname

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }

        If ($Group.securityEnabled)
        {
            $Grouptype = "Security"
        }
        else
        {
            $Grouptype =  [system.String]::Join(" ",$Group.groupType)
        }

        $CurrentGroup = [PSCustomObject]@{
            displayName                    = $Group.displayname
            onPremisesSecurityIdentifier   = $Group.SecurityIdentifier
            objectid                       = $Group.id
            tenantId                       = $Group.organizationId
            email                          = $Group.mail
            groupType                      = $Grouptype
            securityIdentifier             = $Group.securityIdentifier
            description                    = $Group.description
            proxyAddresses                 = $Group.proxyAddress
            createdDateTime                = $Group.createdDateTime
            onPremisesDomainName           = $Group.onPremisesDomainName
            isAssignableToRole             = $Group.isAssignableToRole
            MailNickname                   = $Group.MailNickname
        }
        
        $null = $Coll.Add($CurrentGroup)
    }
    New-Output -Coll $Coll -Type "groups" -Directory $OutputDirectory
   
    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate groups (Privileged Access Group / Role Group)
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    $CollaZGroupRoleAssignments = New-Object System.Collections.ArrayList
    Write-Info "Building role groups object, this may take a few minutes."

    # Use Array from Groups and filter for Role Groups
    $AADGroups = $aadRawGroups | Where-Object {$_.isAssignableToRole -eq "True"}

    $TotalCount = @($AADGroups).Count

    Write-Info "Done building role groups object, processing ${TotalCount} role groups"
    $Progress = 0
    $AADGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.displayname

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing role groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current role group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing role groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current role group: ${DisplayName}"
            } 
        }

        If ($Group.securityEnabled)
        {
            $Grouptype = "Security"
        }
        else
        {
            $Grouptype =  [system.String]::Join(" ",$Group.groupType)
        }

        $CurrentGroup = [PSCustomObject]@{
            displayName                    = $Group.displayname
            objectid                       = $Group.id
            tenantId                       = $Group.organizationId
            email                          = $Group.mail
            groupType                      = $Grouptype
            securityIdentifier             = $Group.securityIdentifier
            description                    = $Group.description
            proxyAddresses                 = $Group.proxyAddress
            createdDateTime                = $Group.createdDateTime
            isAssignableToRole             = $Group.isAssignableToRole
            MailNickname                   = $Group.MailNickname
        }
        
        $null = $Coll.Add($CurrentGroup)

        # Check for eligible members
        Write-Info "Building Azure AD Privileged Group assignments, this may take a few minutes."
        $apiUrl = "$($apiRootAzureAD)/privilegedAccess/aadGroups/resources/$($Group.id)/roleAssignments?`$select=id,resourceId,roleDefinitionId,subjectId,startDateTime,endDateTime,memberType,assignmentState,status"
       
        $data = ""
        $Data = Invoke-RestMethod -Headers $Headers -Uri $apiUrl -Method Get
        $aadRoleGroupAssignments = ($Data | select-object Value).Value

        $TotalCount = $aadRoleGroupAssignments.Count

        Write-Info "Done building role group assignment object, processing ${TotalCount} Azure AD Role Group assignments"
        $Progress = 0

        if($aadRoleGroupAssignments)
        {
            $aadRoleGroupAssignments | ForEach-Object {
                $aadRoleGroupAssignment = $_
                $Progress += 1

                if(![System.String]::IsNullOrEmpty($aadRoleGroupAssignment.endDateTime) -And $aadRoleGroupAssignment.assignmentState -eq "Active")
                {
                    $assignmentState = "ActivatedTo"
                }
                elseif($aadRoleGroupAssignment.assignmentState -eq "Eligible")
                {
                    $assignmentState = "EligibleTo"
                }
                elseif([System.String]::IsNullOrEmpty($aadRoleGroupAssignment.endDateTime) -And $aadRoleGroupAssignment.assignmentState -eq "Active")
                {
                    $assignmentState = "PermanentTo"
                }
                else {
                    $assignmentState = "UnknownTo"
                }
                
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    roleAssignmentId               = $aadRoleGroupAssignment.Id # Role assignment id
                    resourceId                     = $aadRoleGroupAssignment.resourceId # The role Groups id
                    roleDefinitionId               = $aadRoleGroupAssignment.roleDefinitionId #templateid
                    member                         = $aadRoleGroupAssignment.subjectId #member of the role
                    startDateTime                  = $aadRoleGroupAssignment.startDateTime
                    endDateTime                    = $aadRoleGroupAssignment.endDateTime
                    memberType                     = $aadRoleGroupAssignment.memberType
                    assignmentState                = $assignmentState
                    status                         = $aadRoleGroupAssignment.status
                    tenantId                       = $tenantId
                }
                $null = $CollaZGroupRoleAssignments.Add($customObject)
            }

        }
    }
    New-Output -Coll $Coll -Type "rolegroups" -Directory $OutputDirectory
    New-Output -Coll $CollaZGroupRoleAssignments -Type "rolegroupsassignments" -Directory $OutputDirectory

    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate group owners
    # ------------------------------------------------------------------------------------------------------------------------------

    $AADGroups=$aadRawGroups
    $Coll = New-Object System.Collections.ArrayList
    $TargetGroups = $AADGroups | Where-Object {$null -eq $_.OnPremisesSecurityIdentifier}
    $TotalCount = $TargetGroups.Count
    Write-Info "Done building target groups object, processing ${TotalCount} groups"
    $Progress = 0
    $TargetGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.DisplayName

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing group ownerships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing group ownerships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }

        $GroupID = $_.id
        $Owners = Get-AzureADGroupOwner -ObjectId "$GroupID" | Select-Object DisplayName,ObjectID,ObjectType,OnPremisesSecurityIdentifier
        
        ForEach ($Owner in $Owners) {

            $AZGroupOwner = [PSCustomObject]@{
                GroupName       = $Group.DisplayName
                GroupID         = $GroupID
                OwnerName       = $Owner.DisplayName
                OwnerID         = $Owner.ObjectID
                OwnerType       = $Owner.ObjectType
                OwnerOnPremID   = $Owner.OnPremisesSecurityIdentifier
            }
            $null = $Coll.Add($AZGroupOwner)   
        }   
    }
    New-Output -Coll $Coll -Type "groupowners" -Directory $OutputDirectory

    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate group members
    # ------------------------------------------------------------------------------------------------------------------------------

    $AADGroups=$aadRawGroups
    $Coll = New-Object System.Collections.ArrayList
    $TotalCount = @($AADGroups).Count
    Write-Info "Done building groups object, processing ${TotalCount} groups"
    $Progress = 0
    $AADGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.DisplayName

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing group memberships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing group memberships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }

        $GroupID = $_.id
        $Members = Get-AzureADGroupMember -All $True -ObjectId "$GroupID"
        
        ForEach ($Member in $Members) {

            $AZGroupMember = [PSCustomObject]@{
                GroupName = $Group.DisplayName
                GroupID = $GroupID
                GroupOnPremID = $Group.OnPremisesSecurityIdentifier
                MemberName = $Member.DisplayName
                MemberID = $Member.ObjectID
                MemberType = $Member.ObjectType
                MemberOnPremID = $Member.OnPremisesSecurityIdentifier
            }
            $null = $Coll.Add($AZGroupMember)
        }
    }
    New-Output -Coll $Coll -Type "groupmembers" -Directory $OutputDirectory
    
    # ------------------------------------------------------------------------------------------------------------------------------
    # Get devices and their owners
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    Write-Info "Building devices object."
    $AADDevices =  Get-AzureADDevice -All 1 | Where-Object {$_.DeviceOSType -Match "Windows" -Or $_.DeviceOSType -Match "Mac" -Or $_.DeviceOSType -Match "Linux"} | Select-Object Displayname,ObjectID,DeviceId,DeviceOSType,DeviceOSVersion,AccountEnabled,ApproximateLastLogonTimeStamp,ProfileType,DeviceTrustType 
    $TotalCount = @($AADDevices).Count
    Write-Info "Done building devices object, processing ${TotalCount} devices"
    $Progress = 0
    $AADDevices | ForEach-Object {

        $Device = $_
        $DisplayName = $Device.DisplayName

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing devices: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current device: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing devices: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current device: ${DisplayName}"
            } 
        }
        
        $Owner = Get-AzureADDeviceRegisteredOwner -ObjectID $Device.ObjectID | Select-Object Displayname,UserPrincipalName,ObjectId,ObjectType,OnPremisesSecurityIdentifier

        $AzureDeviceOwner = [PSCustomObject]@{
            displayname                  = $Device.Displayname
            objectid                     = $Device.ObjectID
            deviceId                     = $Device.DeviceId
            deviceOs                     = $Device.DeviceOSType
            DeviceOsVersion              = $Device.DeviceOSVersion
            enabled                      = $Device.AccountEnabled
            lastLogonTimeStamp           = $Device.ApproximateLastLogonTimeStamp
            profileType                  = $Device.ProfileType
            trustType                    = $Device.DeviceTrustType
            ownerDisplayName             = $Owner.Displayname
            ownerUserPrincipalName       = $Owner.UserPrincipalName
            ownerID                      = $Owner.ObjectId
            ownerType                    = $Owner.ObjectType
            ownerOnPremisesSecurityIdentifier = $Owner.OnPremisesSecurityIdentifier
        }

        $null = $Coll.Add($AzureDeviceOwner)
    }
    New-Output -Coll $Coll -Type "devices" -Directory $OutputDirectory
    
    # ------------------------------------------------------------------------------------------------------------------------------
    # Azure AD Roles
    # urls: https://gotoguy.blog/2019/11/22/how-to-use-azure-ad-privileged-identity-management-powershell-and-graph-api/
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    Write-Info "Building Azure AD roles object, this may take a few minutes."
    $apiUrl = $apiRootAzureAD + '/privilegedAccess/aadRoles/resources/'+$tenantId+'/roleDefinitions?$select=id,templateId,displayName,type'

    $Data = Invoke-RestMethod -Headers $Headers -Uri $apiUrl -Method Get

    $aadRoleDefinitions = ($Data | select-object Value).Value

    $TotalCount = $aadRoleDefinitions.Count

    Write-Info "Done building ${TotalCount} Azure AD Roles object"

    # ------------------------------------------------------------------------------------------------------------------------------
    # Role Assignments
    # ------------------------------------------------------------------------------------------------------------------------------
    Write-Info "Building Azure AD roles assignments, this may take a few minutes."
    $apiUrl = $apiRootAzureAD + '/privilegedAccess/aadRoles/resources/'+$tenantId+'/roleAssignments?$select=resourceId,roleDefinitionId,subjectId,startDateTime,endDateTime,memberType,assignmentState,status'
    $Data = Invoke-RestMethod -Headers $Headers -Uri $apiUrl -Method Get
    $aadRoleAssignments = ($Data | select-object Value).Value

    $TotalCount = $aadRoleAssignments.Count

    Write-Info "Done building role assignment object, processing ${TotalCount} Azure AD Role assignments"

    $Progress = 0
    $aadRoleAssignments | ForEach-Object {

        $aadRoleAssignment = $_

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        $roledisplayName = $aadRoleDefinitions | Where-Object {$_.templateId -eq "$($aadRoleAssignment.roleDefinitionId)"} | Select-Object -ExpandProperty displayName
        $roleojectid = $aadRoleDefinitions | Where-Object {$_.templateId -eq "$($aadRoleAssignment.roleDefinitionId)"} | Select-Object -ExpandProperty id
        $roleType = $aadRoleDefinitions | Where-Object {$_.templateId -eq "$($aadRoleAssignment.roleDefinitionId)"} | Select-Object -ExpandProperty type
        $roleTemplateId = $aadRoleDefinitions | Where-Object {$_.templateId -eq "$($aadRoleAssignment.roleDefinitionId)"} | Select-Object -ExpandProperty templateId

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing role assignment: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current role assignment: " + $roledisplayName
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing role assignment: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current role assignment: " + $roledisplayName
            } 
        }

        if(![System.String]::IsNullOrEmpty($aadRoleAssignment.endDateTime) -And $aadRoleAssignment.assignmentState -eq "Active")
        {
            $assignmentState = "ActivatedTo"
        }
        elseif($aadRoleAssignment.assignmentState -eq "Eligible")
        {
            $assignmentState = "EligibleTo"
        }
        elseif([System.String]::IsNullOrEmpty($aadRoleAssignment.endDateTime) -And $aadRoleAssignment.assignmentState -eq "Active")
        {
            $assignmentState = "PermanentTo"
        }
        else {
            $assignmentState = "UnknownTo"
        }

        $CurrentRoleAssignment = [PSCustomObject]@{
            roleDisplayName                = $roledisplayName
            roleojectid                    = $roleojectid
            roleTemplateId                 = $roleTemplateId
            roleType                       = $roleType
            roleDefinitionId               = $aadRoleAssignment.roleDefinitionId #templateid
            member                         = $aadRoleAssignment.subjectId #member of the role
            startDateTime                  = $aadRoleAssignment.startDateTime
            endDateTime                    = $aadRoleAssignment.endDateTime
            memberType                     = $aadRoleAssignment.memberType
            assignmentState                = $assignmentState
            status                         = $aadRoleAssignment.status
            tenantId                       = $tenantId
        }
        
        $null = $Coll.Add($CurrentRoleAssignment)
    }
    New-Output -Coll $Coll -Type "rolesAndAssignments" -Directory $OutputDirectory
    Write-Info "Done"

    # ------------------------------------------------------------------------------------------------------------------------------
    # Azure Applications
    # queries: https://graph.microsoft.com/beta/applications
    # ------------------------------------------------------------------------------------------------------------------------------

    Write-Info "Getting Azure Applications, this may take a few minutes."
    
    $CollApplications = New-Object System.Collections.ArrayList
    $CollApplicationOwners = New-Object System.Collections.ArrayList
    Write-Info "Building Service Principals object."
    $applications = Get-AzureADApplication -All 1 | Select-Object ObjectId,ObjectType,AppId,AllowGuestsSignIn,AllowPassthroughUsers,AvailableToOtherTenants,DisplayName,Homepage,IsDisabled,Oauth2AllowImplicitFlow,PublisherDomain,ReplyUrls,WwwHomepage,PasswordCredentials,PublicClient,appRoleAssignmentRequired,KeyCredentials

    $TotalCount = $applications.Count

    If ($TotalCount -gt 1) {
        Write-Info "Done building Applications object, processing ${TotalCount} Applications"
    } else {
        Write-Info "Done building Application object, processing ${TotalCount} Application"
    }

    $Progress = 0
    $applications | ForEach-Object {

        $application = $_

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing Applications: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current Applications: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing Applications: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current Applications: ${DisplayName}"
            } 
        }

        # azApplications
        $CurrentApplication = [PSCustomObject]@{
            objectid                    = $application.ObjectId
            objectType                  = $application.ObjectType
            appId                       = $application.AppId
            allowGuestsSignIn           = $application.AllowGuestsSignIn
            allowPassthroughUsers       = $application.AllowPassthroughUsers
            availableToOtherTenants     = $application.AvailableToOtherTenants
            displayname                 = $application.DisplayName
            homepage                    = $application.Homepage
            wwwHomepage                 = $application.wwwHomepage
            replyUrls                   = $application.ReplyUrls
            isDisabled                  = $application.IsDisabled
            publisherDomain             = $application.publisherDomain
            oauth2AllowImplicitFlow     = $application.oauth2AllowImplicitFlow
            createDateTime              = $application.createDateTime
            description                 = $application.description
            passwordCredentials         = $application.PasswordCredentials
            keyCredentials              = $application.KeyCredentials
            appRoleAssignmentRequired   = $application.appRoleAssignmentRequired
            publicClient                = $application.PublicClient
        }
        $null = $CollApplications.Add($CurrentApplication)

        # Application Owners
        $applicationOwners = Get-AzureADApplicationOwner -ObjectId $application.ObjectId | Select-Object ObjectId,ObjectType,OnPremisesSecurityIdentifier
        $applicationOwners | ForEach-Object {
            $applicationOwner = $_
            $CurrentApplicationOwners = [PSCustomObject]@{
                objectid                    = $application.ObjectId
                appId                       = $application.AppId           
                OwnerID                     = $applicationOwner.ObjectId
                OwnerType                   = $applicationOwner.ObjectType
                OwnerOnPremID               = $applicationOwner.OnPremisesSecurityIdentifier
            }
            $null = $CollApplicationOwners.Add($CurrentApplicationOwners)
        }

    }
    New-Output -Coll $CollApplications -Type "Application" -Directory $OutputDirectory
    New-Output -Coll $CollApplicationOwners -Type "ApplicationOwners" -Directory $OutputDirectory

    # ------------------------------------------------------------------------------------------------------------------------------
    # Azure ServicePrincipals
    # ------------------------------------------------------------------------------------------------------------------------------
    $CollServicePrincipals = New-Object System.Collections.ArrayList
    $CollSpOwners = New-Object System.Collections.ArrayList
    $CollSpAppRoleAssignments = New-Object System.Collections.ArrayList
    $CollSpAppRolePermissions = New-Object System.Collections.ArrayList
    $CollSpAppRoleAssignmentsEveryone = New-Object System.Collections.ArrayList
    $CollSpOAuth2PermissionGrants = New-Object System.Collections.ArrayList
    $CollSpOAuth2PermissionGrantsEveryone = New-Object System.Collections.ArrayList

    #AppRoles of interest in the current version
    $appRoleFilter = @(
        'e2a3a72e-5f79-4c64-b1b1-878b674786c9', # Mail.ReadWrite
        '75359482-378d-4052-8f01-80520e7db3cd', # Files.ReadWrite.All
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7', # Directory.ReadWrite.All
        '7e05723c-0bb0-42da-be95-ae9f08a6e53c', # Domain.ReadWrite.All
        '62a82d76-70ea-41e2-9197-370581804d09', # Group.ReadWrite.All
        '06b708a9-e830-4db3-a914-8e69da51d44f', # AppRoleAssignment.ReadWrite.All
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8', # RoleManagement.ReadWrite.Directory
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9', # Application.ReadWrite.All
        '741f803b-c850-494e-b5df-cde7c675a1ca' # User.ReadWrite.All
    )

    #Dlg of interest in the current version
    $dlgFilter = @(
        'mail.readwrite',
        'files.readwrite.all',
        'directory.accessasuser.all',
        'application.readwrite.all',
        'directory.readwrite.all',
        'domain.readwrite.all',
        'group.readwrite.all',
        'approleassignment.readwrite.all',
        'rolemanagement.readwrite.directory',
        'user_impersonation'
    )

    Write-Info "Building Service Principals object."
    $servicePrincipals = Get-AzureADServicePrincipal -All 1 | Select-Object ObjectId,ObjectType,AccountEnabled,AppDisplayName,AppId,AppOwnerTenantId,DisplayName,PublisherName,ServicePrincipalNames,ServicePrincipalType,KeyCredentials,PasswordCredentials,AppRoleAssignmentRequired
    $TotalCount = $servicePrincipals.Count
    If ($TotalCount -gt 1) {
        Write-Info "Done building Service Principals object, processing ${TotalCount} Service Principals"
    } else {
        Write-Info "Done building Service Principal object, processing ${TotalCount} Service Principal"
    }
    $Progress = 0
    $servicePrincipals | ForEach-Object {

        $servicePrincipal = $_
        $DisplayName = $servicePrincipal.DisplayName

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing Service Principals: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current Service Principals: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing Service Principals: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current Service Principals: ${DisplayName}"
            } 
        }

        $CurrentServicePrincipal = [PSCustomObject]@{
            objectid                    = $servicePrincipal.ObjectId
            appId                       = $servicePrincipal.appId
            objectType                  = $servicePrincipal.ObjectType
            enabled                     = $servicePrincipal.AccountEnabled
            appDisplayName              = $servicePrincipal.AppDisplayName
            appOwnerTenantId            = $servicePrincipal.AppOwnerTenantId
            displayname                 = $servicePrincipal.DisplayName
            publisherName               = $servicePrincipal.PublisherName
            servicePrincipalNames       = $servicePrincipal.ServicePrincipalNames
            servicePrincipalType        = $servicePrincipal.ServicePrincipalType
            keyCredentials              = $servicePrincipal.KeyCredentials
            passwordCredentials         = $servicePrincipal.PasswordCredentials
            AppRoleAssignmentRequired   = $servicePrincipal.AppRoleAssignmentRequired
        }
        $null = $CollServicePrincipals.Add($CurrentServicePrincipal)

        # Service Principals Owners
        $serviceprincipalOwners = Get-AzureADServicePrincipalOwner -ObjectId $servicePrincipal.ObjectId | Select-Object ObjectId,ObjectType,OnPremisesSecurityIdentifier
        $serviceprincipalOwners | ForEach-Object {
            $servicePrincipalOwner = $_
            $CurrentServicePrincipalOwners = [PSCustomObject]@{
                objectid                    = $servicePrincipal.ObjectId
                appId                       = $servicePrincipal.AppId           
                OwnerID                     = $servicePrincipalOwner.ObjectId
                OwnerType                   = $servicePrincipalOwner.ObjectType
                OwnerOnPremID               = $servicePrincipalOwner.OnPremisesSecurityIdentifier
            }
            $null = $CollSpOwners.Add($CurrentServicePrincipalOwners)
        }

        # AppRoleAssignments (Users or Groups that can access the Application) - Who has permissions on principal A?
        if ($servicePrincipal.AppRoleAssignmentRequired -Match "True")
        {
            $ServiceAppRoleAssignments = Get-AzureADServiceAppRoleAssignment -ObjectId $servicePrincipal.ObjectId | Select-Object PrincipalId, PrincipalType

            $ServiceAppRoleAssignments | ForEach-Object {
                $ServiceAppRoleAssignment = $_
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    servicePrincipalObjectId    = $servicePrincipal.ObjectId
                    appId                       = $servicePrincipal.appId
                    principalType               = $ServiceAppRoleAssignment.PrincipalType
                    principalId                 = $ServiceAppRoleAssignment.PrincipalId  # Azure AD User or Azure Ad Group (Only directly assigned members have access)     
                }
                $null = $CollSpAppRoleAssignments.Add($customObject)
            }            
        }
        else 
        {
            # Dump only Apps that Everyone can access from our Tenant
            If ($servicePrincipal.AppOwnerTenantId -Match $tenantId)
            {
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    servicePrincipalObjectId    = $servicePrincipal.ObjectId
                    appId                       = $servicePrincipal.appId
                    principalType               = "Everyone"
                    PrincipalId                 = $tenantId  # Everyone     
                }
                $null = $CollSpAppRoleAssignmentsEveryone.Add($customObject)
            }
        }              

        # AppPermission - What application permissions have been assigned to the service principal?
        $spAppRolePermissions = Get-AzureADServiceAppRoleAssignedTo -ObjectId $servicePrincipal.ObjectId -All 1 | Select-Object PrincipalId,PrincipalType,ResourceId,ResourceDisplayName,Id,PrincipalDisplayName

        $spAppRolePermissions | ForEach-Object {
            $spAppRolePermission = $_

            #Translate Rights
            $getAppRoles = Get-AzureADServicePrincipal -ObjectId $spAppRolePermission.ResourceId | Select-Object AppRoles
            $getAppRoles = $getApproles.Approles

            $getAppRole = $getAppRoles | Where-Object {$_.Id -eq $spAppRolePermission.Id } | Select-Object Description,Displayname,Value,Id

            if ($appRoleFilter -contains $getAppRole.id.ToLower())
            { 
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    permissionType              = "Application"
                    servicePrincipalObjectId    = $servicePrincipal.ObjectId
                    appId                       = $servicePrincipal.appId
                    appRoleId                   = $spAppRolePermission.id # Role Permission Id
                    appRoleIdd                  = $getAppRole.id # Role Permission Id from Sp
                    appRoleValue                = $getAppRole.Value -replace '\.', '' # Role Permission Value -> TeamsTab.ReadWrite.All
                    appDisplayname              = $getAppRole.DisplayName # Role Permission Value -> Read and write tabs in Microsoft Teams
                    appDescription              = $getAppRole.Description # Role Permission Value -> Read and write tabs in Microsoft Teams
                    principalDisplayName        = $spAppRolePermission.PrincipalDisplayName # e.g. Test
                    principalId                 = $spAppRolePermission.PrincipalId  # e.g. Service Principal Id
                    principalType               = $spAppRolePermission.PrincipalType # e.g. Service Principal   
                    resourceId                  = $spAppRolePermission.ResourceId # e.g. Microsoft Graph SP id
                    resourceDisplayName         = $spAppRolePermission.ResourceDisplayName # e.g. Microsoft Graph
                    tenantId                    = $tenantId
                }
                $null = $CollSpAppRolePermissions.Add($customObject)
            }
        }
        
        # Get the OAuth2 (Delegated) Permission Grants
        $spOAuth2PermissionGrants =  Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $servicePrincipal.ObjectId | Select-Object ClientId,ConsentType,PrincipalId,ResourceId,Scope
        
        if($spOAuth2PermissionGrants)
        {
            $spOAuth2PermissionGrants | ForEach-Object {
                $spOAuth2PermissionGrant = $_

                if ($spOAuth2PermissionGrant.Scope) 
                {
                    # Split Scope permissions + Remote spaces at the beginning and at the end #@!?
                    $scopes = $spOAuth2PermissionGrant.Scope.trim().Split(" ") 
                    $scopes | ForEach-Object {
                        $scope = $_
                        if ($dlgFilter -contains $scope.ToLower())
                        {
                            #Translate Rights -> Replace with Caching in the future
                            #e.g. https://github.com/CIOTechnologySolutions/ActiveDirectory/blob/master/Get-AzureADPSPermissions.ps1
                            $getOauth2Permissions = Get-AzureADServicePrincipal -ObjectId $spOAuth2PermissionGrant.ResourceId | Select-Object Oauth2Permissions
                            $getOauth2Permissions = $getOauth2Permissions.OAuth2Permissions
                            $getOauth2Permission = $getOauth2Permissions | Where-Object {$_.Value -eq $scope } | Select-Object UserConsentDescription,UserConsentDisplayName,Value,Id

                            # Delegations for Everyone or only for specific principals
                            If ($spOAuth2PermissionGrant.ConsentType -Match "AllPrincipals")
                            {
                                # The logic to verify if the App requires assignment or is disabled was removed -> Check with Graph Query
                                $customObject = ""
                                $customObject = [PSCustomObject]@{
                                    permissionType                  = "Delegated"
                                    servicePrincipalObjectId        = $servicePrincipal.ObjectId
                                    appId                           = $servicePrincipal.appId
                                    consentType                     = $spOAuth2PermissionGrant.ConsentType
                                    oAuth2scope                     = $scope -replace '\.', '' -replace '_', '' # user_impersonation
                                    oAuth2UserConsentDisplayName    = $getOauth2Permission.UserConsentDisplayName # Have full access to Visual Studio Team Services REST APIs
                                    oAuth2UserConsentDescription    = $getOauth2Permission.UserConsentDescription # Allow the application full access to the REST APIs provided by Visual Studio Team Services on your behalf
                                    principalId                     = "Everyone"
                                    resourceId                      = $spOAuth2PermissionGrant.ResourceId # e.g. Microsoft Graph SP id
                                    clientId                        = $spOAuth2PermissionGrant.ClientId # e.g. 
                                    tenantId                        = $tenantId
                                }
                                $null = $CollSpOAuth2PermissionGrantsEveryone.Add($customObject)
                            }
                            else 
                            {
                                # The logic to verify if the App requires assignment or is disabled was removed -> Check with Graph Query
                                $customObject = ""
                                $customObject = [PSCustomObject]@{
                                    permissionType                  = "Delegated"
                                    servicePrincipalObjectId        = $servicePrincipal.ObjectId
                                    appId                           = $servicePrincipal.appId
                                    consentType                     = $spOAuth2PermissionGrant.ConsentType
                                    oAuth2scope                     = $scope -replace '\.', '' -replace '_', '' # user_impersonation
                                    oAuth2UserConsentDisplayName    = $getOauth2Permission.UserConsentDisplayName # Have full access to Visual Studio Team Services REST APIs
                                    oAuth2UserConsentDescription    = $getOauth2Permission.UserConsentDescription # Allow the application full access to the REST APIs provided by Visual Studio Team Services on your behalf
                                    principalId                     = $spOAuth2PermissionGrant.PrincipalId  # e.g. marius  
                                    resourceId                      = $spOAuth2PermissionGrant.ResourceId # e.g. Microsoft Graph SP id
                                    clientId                        = $spOAuth2PermissionGrant.ClientId # e.g. Graph Explorer
                                    tenantId                        = $tenantId
                                }
                                $null = $CollSpOAuth2PermissionGrants.Add($customObject)       
                            }
                        }
                    }
                }
            }
        }
    }
    # CSV Output
    New-Output -Coll $CollServicePrincipals -Type "ServicePrincipals" -Directory $OutputDirectory
    New-Output -Coll $CollSpOwners -Type "SpOwners" -Directory $OutputDirectory
    New-Output -Coll $CollSpAppRoleAssignments -Type "SpAppRoleAssignments" -Directory $OutputDirectory
    New-Output -Coll $CollSpAppRoleAssignmentsEveryone -Type "SpAppRoleAssignmentsEveryone" -Directory $OutputDirectory
    New-Output -Coll $CollSpAppRolePermissions -Type "SpAppRolePermissions" -Directory $OutputDirectory
    New-Output -Coll $CollSpOAuth2PermissionGrants -Type "SpOAuth2PermissionGrants" -Directory $OutputDirectory
    New-Output -Coll $CollSpOAuth2PermissionGrantsEveryone -Type "SpOAuth2PermissionGrantsEveryone" -Directory $OutputDirectory

    # ------------------------------------------------------------------------------------------------------------------------------
    # Azure DevOps
    # ------------------------------------------------------------------------------------------------------------------------------

    # Define DevOps Array Lists
    $CollaZDevopsOrgs = New-Object System.Collections.ArrayList
    $CollaZDevopsGroups = New-Object System.Collections.ArrayList
    $CollaZDevopsUsers = New-Object System.Collections.ArrayList
    $CollaZDevopsMemberships = New-Object System.Collections.ArrayList
    $CollaZDevopsProjects = New-Object System.Collections.ArrayList
    $CollaZDevopsSpns = New-Object System.Collections.ArrayList

    # Get Azure DevOps Access Token
    # 499b84ac-1321-427f-aa17-267ca6975798 = DevOps API Endpoint
    $token = (Get-AzAccessToken -ResourceUrl "499b84ac-1321-427f-aa17-267ca6975798").Token
    $header = @{
        'Authorization' = 'Bearer ' + $token
        'Content-Type' = 'application/json'
    }

    # Get User Profile Access Data
    $URL = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=6.0"

    $Data = Invoke-RestMethod -Method GET -Uri $URL -Headers $header
    $aZDevopsProfile = $Data

    # Get Organizations
    $URL = "https://app.vssps.visualstudio.com/_apis/accounts?memberId=$($aZDevopsProfile.publicAlias)&api-version=6.0"
    $Data = Invoke-RestMethod -Method GET -Uri $URL -Headers $header
    $aZDevopsOrgs= ($Data | select-object Value).Value

    # Get Entities from all Organizations
    $aZDevopsOrgs | ForEach-Object {
        $aZDevopsOrg = $_

        $customObject = ""
        $customObject = [PSCustomObject]@{
            accountName                     = $aZDevopsOrg.accountName
            accountUri                      = $aZDevopsOrg.accountUri
            accountId                       = $aZDevopsOrg.accountId
        }
        $null = $CollaZDevopsOrgs.Add($customObject) 

        # Get all Projects
        $URL = "https://dev.azure.com/$($aZDevopsOrg.accountName)/_apis/projects?api-version=7.1-preview.4"
        $Data = Invoke-RestMethod -Method GET -Uri $URL -Headers $header
        Write-Info "Azure DevOps Projects"
        $azDevOpsProjects = ($Data | select-object Value).Value
        $azDevOpsProjects | ForEach-Object {
            $azDevOpsProject = $_

            $customObject = ""
            $customObject = [PSCustomObject]@{
                organizationId         = $aZDevopsOrg.accountId
                projectid              = $azDevOpsProject.id
                name                   = $azDevOpsProject.name
                visibility             = $azDevOpsProject.visibility
            }
            $null = $CollaZDevopsProjects.Add($customObject)           

            # Get Service Principals from Projects
            $URL = "https://dev.azure.com/$($aZDevopsOrg.accountName)/$($azDevOpsProject.name)/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4"
            $Data = Invoke-RestMethod -Method GET -Uri $URL -Headers $header
            Write-Info "Azure DevOps Project Details"
            $azDevOpsProjectDetails = ($Data | select-object Value).Value

            $azDevOpsProjectDetails | ForEach-Object {

                $azDevOpsProjectDetail = $_

                if ($azDevOpsProjectDetail.type -eq "azurerm")
                {
                    $customObject = ""
                    $customObject = [PSCustomObject]@{
                        projectId              = $azDevOpsProject.id
                        spnObjectId            = $azDevOpsProjectDetail.data.spnObjectId
                        appObjectId            = $azDevOpsProjectDetail.data.appObjectId
                    }
                    $null = $CollaZDevopsSpns.Add($customObject)           
                }
            }
        }
        
        # Get all Groups from all Organizations
        $URL = "$($aZDevopsOrg.accountUri)_apis/graph/groups?api-version=6.0-preview.1"
        $Data = Invoke-RestMethod -Method GET -Uri $URL -Headers $header
        Write-Info "Azure DevOps Groups Object"
        $aZDevopsGroups = ($Data | select-object Value).Value

        $TotalCount = $aZDevopsGroups.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building Azure DevOps Groups object, processing ${TotalCount} Azure DevOps Groups"
        } else {
            Write-Info "Done building Azure DevOps Groups object, processing ${TotalCount} Azure DevOps Groups"
        }

        $aZDevopsGroups | ForEach-Object {

            $aZDevopsGroup = $_

            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
    
            If ($Progress -eq $TotalCount) {
                Write-Info "Processing Azure DevOps Group: [${Progress}/${TotalCount}][${ProgressPercentage}%] Azure DevOps Group: ${$aZDevopsGroup.displayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing Azure DevOps Group: [${Progress}/${TotalCount}][${ProgressPercentage}%] Azure DevOps Group: ${$aZDevopsGroup.displayName}"
                } 

            }

            # Get Org or Prj Id from domain string
            $domainId = $aZDevopsGroup.domain.Substring($aZDevopsGroup.domain.LastIndexOf("/")+1)

            $customObject = ""
            $customObject = [PSCustomObject]@{
                subjectKind                     = $aZDevopsGroup.subjectKind
                description                     = $aZDevopsGroup.description
                principalName                   = $aZDevopsGroup.principalName
                displayName                     = $aZDevopsGroup.displayName
                descriptor                      = $aZDevopsGroup.descriptor
                domainId                        = $domainId
                accountName                     = $aZDevopsOrg.accountName
                accountUri                      = $aZDevopsOrg.accountUri
                accountId                       = $aZDevopsOrg.accountId
                originId                        = $aZDevopsGroup.originId # objectId in AzureAD
            }
            $null = $CollaZDevopsGroups.Add($customObject)  

            $URL = "$($aZDevopsOrg.accountUri)_apis/graph/Memberships/$($aZDevopsGroup.descriptor)?direction=Down&api-version=6.0-preview.1"
            $Data = Invoke-RestMethod -Method GET -Uri $URL -Headers $header
            $aZDevopsMemberships = ($Data | select-object Value).Value
            if($aZDevopsMemberships)
            {
                $aZDevopsMemberships | ForEach-Object {
                    $aZDevopsMembership = $_
                    $customObject = ""
                    $customObject = [PSCustomObject]@{
                        containerDescriptor             = $aZDevopsMembership.containerDescriptor
                        memberDescriptor                = $aZDevopsMembership.memberDescriptor
                    }
                    $null = $CollaZDevopsMemberships.Add($customObject)  
                }
            }
        }

        # Get all Users from all Organizations
        $URL = "$($aZDevopsOrg.accountUri)_apis/graph/users?api-version=6.0-preview.1"
        $Data = Invoke-RestMethod -Method GET -Uri $URL -Headers $header
        $aZDevopsUsers = ($Data | select-object Value).Value

        $aZDevopsUsers | ForEach-Object {
            $aZDevopsUser = $_
            $customObject = ""
            $customObject = [PSCustomObject]@{
                subjectKind                     = $aZDevopsUser.subjectKind
                directoryAlias                  = $aZDevopsUser.directoryAlias
                principalName                   = $aZDevopsUser.principalName
                mailAddress                     = $aZDevopsUser.mailAddress
                displayName                     = $aZDevopsUser.displayName
                descriptor                      = $aZDevopsUser.descriptor
                accountName                     = $aZDevopsOrg.accountName
                accountUri                      = $aZDevopsOrg.accountUri
                accountId                       = $aZDevopsOrg.accountId
                tenant                          = $aZDevopsUser.domain
                origin                          = $aZDevopsUser.origin
                originId                        = $aZDevopsUser.originId # objectId in AzureAD
            }
            $null = $CollaZDevopsUsers.Add($customObject)  
        }
    }
    # CSV Output
    New-Output -Coll $CollaZDevopsOrgs -Type "DevOpsOrgs" -Directory $OutputDirectory
    New-Output -Coll $CollaZDevopsGroups -Type "DevOpsGroups" -Directory $OutputDirectory
    New-Output -Coll $CollaZDevopsUsers -Type "DevOpsUsers" -Directory $OutputDirectory
    New-Output -Coll $CollaZDevopsMemberships -Type "DevOpsMemberships" -Directory $OutputDirectory
    New-Output -Coll $CollaZDevopsProjects -Type "DevOpsProjects" -Directory $OutputDirectory
    New-Output -Coll $CollaZDevopsSpns -Type "DevOpsSpns" -Directory $OutputDirectory

    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate ManagementGroups
    # Role Eligble Assignments over PIM via:
    # https://docs.microsoft.com/en-us/rest/api/authorization/role-eligibility-schedule-requests/list-for-scope#code-try-0
    # ------------------------------------------------------------------------------------------------------------------------------

    $CollaZArmMgmrGroups = New-Object System.Collections.ArrayList
    $CollaZArmRoles = New-Object System.Collections.ArrayList
    $CollaZArmRoleAssignments = New-Object System.Collections.ArrayList
    $CollaZArmMgmrGroupChilds = New-Object System.Collections.ArrayList

    Write-Info "Building ManagementGroup(s) object."
    $AADMgmtGroup = Get-AzManagementGroup | Select-Object Id,Name,TenantId,DisplayName
    $TotalCount = $AADMgmtGroup.Count
    If ($TotalCount -gt 1) {
        Write-Info "Done building Management Groups object, processing ${TotalCount} Management Groups"
    } else {
        Write-Info "Done building Management Groups object, processing ${TotalCount} Management Groups"
    }
    $Progress = 0
    # Get all Management Groups
    $AADMgmtGroup | ForEach-Object {

        $MgmtGroup = $_
        $DisplayName = $MgmtGroup.Name

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing Management Groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current Management Group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing Management Groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current Management Group: ${DisplayName}"
            } 
        }

        # Get Children and Parent information of a Mgmt Group
        $MgmtGroupExpand= Get-AzManagementGroup -Expand $MgmtGroup.Name | Select-Object Id,ParentId,Children
        $MgmtGroupExpand.Children | ForEach-Object {

            $MgmtGroupChild = $_
            $customObject = ""
            $customObject = [PSCustomObject]@{
                parentId            = $MgmtGroup.Id
                childId             = $MgmtGroupChild.Id
            }
            $null = $CollaZArmMgmrGroupChilds.Add($customObject)
        }

        # Create Management Group Object
        $customObject = ""
        $customObject = [PSCustomObject]@{
            objectid            = $MgmtGroup.Id
            name                = $MgmtGroup.Name
            displayname         = $MgmtGroup.DisplayName
            tenantId            = $MgmtGroup.TenantId
            parentId            = $MgmtGroupExpand.ParentId
        }
        $null = $CollaZArmMgmrGroups.Add($customObject)

        # Get all RBAC Roles and Members
        #$armRoles= Get-AzRoleAssignment -scope $MgmtGroup.Id | Where-Object {$_.Scope -eq "/"}
        $armRoles= Get-AzRoleAssignment -scope $MgmtGroup.Id
        $armRoles | ForEach-Object {

            $armRole = $_
            
            # Generate Custom Role Id
            $customRoleId = $MgmtGroup.Id + "/" + $armRole.RoleDefinitionId

            # Role Array - discard if role is already in the Array
            if($CollaZArmRoles.objectid -notcontains $customRoleId)
            {
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    objectid                  = $customRoleId
                    roleDefinitionId          = $armRole.RoleDefinitionId
                    roleDefinitionName        = $armRole.RoleDefinitionName
                    scopeId                   = $MgmtGroup.Id # Where the Role will be assigned

                }
                $null = $CollaZArmRoles.Add($customObject)  
            }

            # Membership Array
            $customObject = ""
            $customObject = [PSCustomObject]@{
                roleId                    = $customRoleId # Role Id 
                principalId               = $armRole.ObjectId # Member Object
                principalType             = $armRole.ObjectType # Member Object Type
                roleAssignmentId          = $armRole.RoleAssignmentId # AssignmentId
            }
            $null = $CollaZArmRoleAssignments.Add($customObject) 
        }

    }
    

    New-Output -Coll $CollaZArmMgmrGroups -Type "ArmMgmtGroups" -Directory $OutputDirectory
    New-Output -Coll $CollaZArmMgmrGroupChilds -Type "ArmMgmtGroupsChilds" -Directory $OutputDirectory
    
    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate subscriptions
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    Write-Info "Building subscription(s) object."
    $AADSubscriptions = Get-AzSubscription | Select-Object Id,Name,State,SubscriptionId,TenantId,HomeTenantId,Tags
    $TotalCount = $AADSubscriptions.Count
    If ($TotalCount -gt 1) {
        Write-Info "Done building subscription object, processing ${TotalCount} subscription"
    } else {
        Write-Info "Done building subscriptions object, processing ${TotalCount} subscriptions"
    }
    $Progress = 0
    $AADSubscriptions | ForEach-Object {

        $Subscription = $_
        $DisplayName = $Subscription.Name

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing subscriptions: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current subscription: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing subscriptions: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current subscription: ${DisplayName}"
            } 
        }
        $subscriptionObjectId = "/subscriptions/" + $Subscription.Id
        $Current = [PSCustomObject]@{
            objectid            = $subscriptionObjectId
            displayname         = $Subscription.Name
            subscriptionId      = $Subscription.SubscriptionId
            tenantId            = $Subscription.TenantId
            homeTenantId        = $Subscription.HomeTenantId
            state               = $Subscription.State
            tags                = $Subscription.Tags
        }
        $null = $Coll.Add($Current)

        # Get all RBAC Roles and Members
        $armRoles= Get-AzRoleAssignment -scope $subscriptionObjectId | Where-Object {$_.Scope -eq $subscriptionObjectId}
        $armRoles | ForEach-Object {

            $armRole = $_
            
            # Generate Custom Role Id
            $customRoleId = $subscriptionObjectId + "/" + $armRole.RoleDefinitionId

            # Role Array - discard if role is already in the Array
            if($CollaZArmRoles.objectid -notcontains $customRoleId)
            {
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    objectid                  = $customRoleId
                    roleDefinitionId          = $armRole.RoleDefinitionId
                    roleDefinitionName        = $armRole.RoleDefinitionName
                    scopeId                   = $subscriptionObjectId # Where the Role will be assigned

                }
                $null = $CollaZArmRoles.Add($customObject)
            }

            # Membership Array
            $customObject = ""
            $customObject = [PSCustomObject]@{
                roleId                    = $customRoleId # Role Id 
                principalId               = $armRole.ObjectId # Member Object
                principalType             = $armRole.ObjectType # Member Object Type
                roleAssignmentId          = $armRole.RoleAssignmentId # AssignmentId
            }
            $null = $CollaZArmRoleAssignments.Add($customObject) 
        }
    }
    New-Output -Coll $Coll -Type "subscriptions" -Directory $OutputDirectory
    
    # ------------------------------------------------------------------------------------------------------------------------------
    # Enumerate resource groups
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building resource groups object for subscription ${SubDisplayName}"
        $AADResourceGroups = Get-AzResourceGroup
        $TotalCount = $AADResourceGroups.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building resource group object, processing ${TotalCount} resource group"
        } else {
            Write-Info "Done building resource groups object, processing ${TotalCount} resource groups"
        }
        $Progress = 0
    
        $AADResourceGroups | ForEach-Object {

            $RG = $_
            $DisplayName = $RG.ResourceGroupName

            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
                } 
            }
        
            $id = $RG.resourceid
            $resourceSub = "$id".split("/", 4)[2]

            $ResourceGroup = [PSCustomObject]@{
                displayname         = $RG.ResourceGroupName
                subscriptionId      = $resourceSub
                resourceGroupId     = $RG.ResourceId
            }
        
            $null = $Coll.Add($ResourceGroup)

            # Get all RBAC Roles and Members
            $armRoles= Get-AzRoleAssignment -scope $RG.ResourceId | Where-Object {$_.Scope -eq $RG.ResourceId }
            $armRoles | ForEach-Object {

                $armRole = $_
                
                # Generate Custom Role Id
                $customRoleId = $RG.ResourceId + "/" + $armRole.RoleDefinitionId

                # Role Array - discard if role is already in the Array
                if($CollaZArmRoles.objectid -notcontains $customRoleId)
                {
                    $customObject = ""
                    $customObject = [PSCustomObject]@{
                        objectid                  = $customRoleId
                        roleDefinitionId          = $armRole.RoleDefinitionId
                        roleDefinitionName        = $armRole.RoleDefinitionName
                        scopeId                   = $RG.ResourceId # Where the Role will be assigned

                    }
                    $null = $CollaZArmRoles.Add($customObject)
                }

                # Membership Array
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    roleId                    = $customRoleId # Role Id 
                    principalId               = $armRole.ObjectId # Member Object
                    principalType             = $armRole.ObjectType # Member Object Type
                    roleAssignmentId          = $armRole.roleAssignmentId # AssignmentId
                }
                $null = $CollaZArmRoleAssignments.Add($customObject) 
            }
        }
    }

    New-Output -Coll $Coll -Type "resourcegroups" -Directory $OutputDirectory

    $Coll = New-Object System.Collections.ArrayList

    # ------------------------------------------------------------------------------------------------------------------------------
    # Get VMs
    # ------------------------------------------------------------------------------------------------------------------------------

    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building VMs object for subscription ${SubDisplayName}"
        $AADVirtualMachines = Get-AzVM -status | Select-Object Id,Name,VmId,PowerState,LicenseType,Tags,ResourceGroupName
        $TotalCount = $AADVirtualMachines.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building VM object, processing ${TotalCount} virtual machine"
        } else {
            Write-Info "Done building VMs object, processing ${TotalCount} virtual machines"
        }
        $Progress = 0
    
        $AADVirtualMachines | ForEach-Object {
        
            $VM = $_
            $DisplayName = $VM.Name

            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current virtual machine: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current virtual machine: ${DisplayName}"
                } 
            }
        
            $RGName = $VM.ResourceGroupName
            #$RGID = (Get-AzResourceGroup "$RGName").ResourceID
            $vmid = $VM.Id
            $RgIdSplit = "$vmid".split("/", 6)
            $RGID = "/" + $RgIdSplit[1] + "/" + $RgIdSplit[2] + "/" + $RgIdSplit[3] + "/" + $RgIdSplit[4]
        
            $id = $VM.id
            $resourceSub = "$id".split("/", 4)[2]

            $AzVM = [PSCustomObject]@{
                objectid = $VM.Id
                vmId = $VM.VmId
                displayname = $VM.Name
                resourceGroupName = $RGName
                resoucreGroupSub = $resourceSub
                resourceGroupId = $RGID
                powerState = $VM.PowerState
                licenseType = $VM.LicenseType
                tags = $VM.Tags
            }

            $null = $Coll.Add($AzVM)

            # Get all RBAC Roles and Members
            $armRoles= Get-AzRoleAssignment -scope $VM.id | Where-Object {$_.Scope -eq $VM.id }
            $armRoles | ForEach-Object {

                $armRole = $_
                
                # Generate Custom Role Id
                $customRoleId = $VM.id + "/" + $armRole.RoleDefinitionId

                # Role Array - discard if role is already in the Array
                if($CollaZArmRoles.objectid -notcontains $customRoleId)
                {
                    $customObject = ""
                    $customObject = [PSCustomObject]@{
                        objectid                  = $customRoleId
                        roleDefinitionId          = $armRole.RoleDefinitionId
                        roleDefinitionName        = $armRole.RoleDefinitionName
                        scopeId                   = $VM.id # Where the Role will be assigned

                    }
                    $null = $CollaZArmRoles.Add($customObject)
                }

                # Membership Array
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    roleId                    = $customRoleId # Role Id 
                    principalId               = $armRole.ObjectId # Member Object
                    principalType             = $armRole.ObjectType # Member Object Type
                    roleAssignmentId          = $armRole.roleAssignmentId # AssignmentId
                }
                $null = $CollaZArmRoleAssignments.Add($customObject) 
            }
        
        }
    }
    New-Output -Coll $Coll -Type "vms" -Directory $OutputDirectory
    
    # ------------------------------------------------------------------------------------------------------------------------------
    # Get KeyVaults
    # ------------------------------------------------------------------------------------------------------------------------------

    $Coll = New-Object System.Collections.ArrayList
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building key vaults object for subscription ${SubDisplayName}"
    
        $AADKeyVaults = Get-AzKeyVault | Select-Object VaultName,ResourceId,Tags,ResourceGroupName
        $TotalCount = @($AADKeyVaults).Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building key vaults object, processing ${TotalCount} key vaults"
        } else {
            Write-Info "Done building key vault object, processing ${TotalCount} key vault"
        }
        $Progress = 0
        
        $AADKeyVaults | ForEach-Object {
        
            $KeyVault = $_
            $DisplayName = $KeyVault.VaultName

            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
                } 
            }
        
            $RGName = $KeyVault.ResourceGroupName
            #$RGID = (Get-AzResourceGroup "$RGName").ResourceID
            $ResourceId = $KeyVault.ResourceId
            $RgIdSplit = "$ResourceId".split("/", 6)
            $RGID = "/" + $RgIdSplit[1] + "/" + $RgIdSplit[2] + "/" + $RgIdSplit[3] + "/" + $RgIdSplit[4]

            $resourceSub = "$ResourceId".split("/", 4)[2]

            $AzKeyVault = [PSCustomObject]@{
                displayname         = $KeyVault.VaultName
                objectid            = $KeyVault.ResourceId
                resourceGroupName   = $RGName
                resoucreGroupSub    = $resourceSub
                resourceGroupId     = $RGID
                tags                = $KeyVault.Tags
            }
            $null = $Coll.Add($AzKeyVault)

            # Get all RBAC Roles and Members
            $armRoles= Get-AzRoleAssignment -scope $KeyVault.ResourceId | Where-Object {$_.Scope -eq $KeyVault.ResourceId }
            $armRoles | ForEach-Object {

                $armRole = $_
                
                # Generate Custom Role Id
                $customRoleId = $KeyVault.ResourceId + "/" + $armRole.RoleDefinitionId

                # Role Array - discard if role is already in the Array
                if($CollaZArmRoles.objectid -notcontains $customRoleId)
                {
                    $customObject = ""
                    $customObject = [PSCustomObject]@{
                        objectid                  = $customRoleId
                        roleDefinitionId          = $armRole.RoleDefinitionId
                        roleDefinitionName        = $armRole.RoleDefinitionName
                        scopeId                   = $KeyVault.ResourceId # Where the Role will be assigned

                    }
                    $null = $CollaZArmRoles.Add($customObject)
                }

                # Membership Array
                $customObject = ""
                $customObject = [PSCustomObject]@{
                    roleId                    = $customRoleId # Role Id 
                    principalId               = $armRole.ObjectId # Member Object
                    principalType             = $armRole.ObjectType # Member Object Type
                    roleAssignmentId          = $armRole.roleAssignmentId # AssignmentId
                }
                $null = $CollaZArmRoleAssignments.Add($customObject) 
            }
        }
    }
    New-Output -Coll $Coll -Type "keyvaults" -Directory $OutputDirectory

    # ARM Roles Output
    New-Output -Coll $CollaZArmRoles -Type "ArmRoles" -Directory $OutputDirectory
    New-Output -Coll $CollaZArmRoleAssignments -Type "ArmRoleAssignments" -Directory $OutputDirectory

    # ------------------------------------------------------------------------------------------------------------------------------
    # Compressing files
    # ------------------------------------------------------------------------------------------------------------------------------ 

    Write-Host "Compressing files"
    $location = Get-Location
    $name = $date + "-azurecollection"
    If($OutputDirectory.path -eq $location.path){
        $jsonpath = $OutputDirectory.Path + [IO.Path]::DirectorySeparatorChar + "$date-*.json"
        $destinationpath = $OutputDirectory.Path + [IO.Path]::DirectorySeparatorChar + "$name.zip"
    }
    else{
        $jsonpath = $OutputDirectory + [IO.Path]::DirectorySeparatorChar + "$date-*.json"
        $destinationpath = $OutputDirectory + [IO.Path]::DirectorySeparatorChar + "$name.zip"
    }

    $error.Clear()
    try {
        Compress-Archive $jsonpath -DestinationPath $destinationpath
    }
    catch {
        Write-Host "Zip file creation failed, JSON files may still be importable."
    }
    if (!$error) {
        Write-Host "Zip file created: $destinationpath"
        Remove-Item $jsonpath
        Write-Host "Done! Drag and drop the zip into the BloodHound GUI to import data."
    }
}
