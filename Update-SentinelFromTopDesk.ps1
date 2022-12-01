<#
.SYNOPSIS
    Webhook for receiving action data from TopDesk and updating incidents in Microsoft Sentinel
    
.DESCRIPTION
	This script is designed to run as a webhook in Azure Automation.  TopDesk is configured to trigger this webhook based on certain actions
	within the system.  TopDesk sends JSON data linking to a Sentinel Incident and this webhook processes that JSON data and updates the
	incident accordingly.

	Handles:
		1) Status updates and incident assignment
		2) Actions added to TopDesk tickets
		3) Ticket and incident closure and classification.

	Author: Gino Caroli
	Change Log:
		10/05/22	Initial Release
		10/19/22	Updated to properly handle 'Undetermined' classification
#>
param
(
    [Parameter(Mandatory=$false)]
    [object] $WebhookData
)

Function GetSecret ($vault,$name) {
    try {
        $secret = Get-AzKeyVaultSecret -VaultName $vault -Name $name -AsPlainText
        $secret
    } catch {
        ("Failed to retrieve {0} secret from vault {1}." -f $name,$vault)
        Write-Error -Message $_.Exception
        throw $_.Exception
        Exit -1
    }
}

import-module AZ.KeyVault
import-module AZ.Accounts

$json = (ConvertFrom-Json -InputObject $WebHookData.RequestBody)
$json | format-list

$errorActionPreference = "Stop"
$topdeskEnvironment = "prod"

# KeyVault Variables
$kvName = "**KeyVault Name**"
$kvResourceGroup = "**KeyVault Resource Group**"
$kvAutomationAccount = "**Automation Account Object ID**"

# TopDesk Variables - instance url, keyvault secret name and Processing Status GUID for re-opening tickets
if ($topdeskEnvironment -eq "test") {
	$kvSecretName = "**KeyVault Secret Name**"
	$topdeskurl = "**InstanceName**-test.topdesk.net"
	$processingStatusID = "**TopDesk Processing Status GUID**" # Logged
} else {
	$kvSecretName = "**KeyVault Secret Name**"
	$topdeskurl = "**InstanceName**.topdesk.net"
	$processingStatusID = "**TopDesk Processing Status GUID**" # Logged
}

# Main Variables
$tenantID = "**AAD TenantID**"
$rgname = '**Sentinel Resource Group Name**'
$wsname = '**LogAnalytics Workspace Name**'
$subscriptionid = '**Azure Subscription ID**'
$sentinelclassifications = @("True positive - suspicious activity","Benign Positive - suspicious but expected","False Positive - incorrect alert logic","False Positive - inaccurate data","Undetermined")

try {
	write-output ("Connecting to Azure Subscription {0}" -f $subscriptionid)
	Connect-AzAccount -Identity -Subscription $subscriptionid -Tenant $tenantid | Out-Null

	write-output ("Retrieving Sentinel incident {0}" -f $json.incidentid)
	$incident = get-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid

	write-output ("Got Sentinel incident: {0} - {1}" -f $incident.IncidentNumber,$incident.title)

	# If the calling TopDesk Action is "Sentinel - Send Operator/Status Data" or "Sentinel - Close Incident"
	if ($json.process -eq "1" -or $json.process -eq "3") {
		Write-Output "Calling TopDesk Action is: Sentinel - Send Operator/Status Data"
		# Check the ownership of the ticket.  If the incident has no owner, assign the sentinel incident to the ticket owner
		# mapping the TopDesk owner to their admin credential.
		#
		$incidentOwner = $incident.Owner
		$incidentStatus = $incident.Status

		if ($incidentOwner.AssignedTo -eq $null) {
			write-output ("Incident {0} has no owner" -f $json.incidentid)
			if ($json.operator -ne 'Cyber Response Team') {
				# ********************************************************************************
				# *** This will need to change with additional operators in Sentinel & TopDesk ***
				# ********************************************************************************
				#
				# Get the AAD User object for the Sentinel Operator to build the Owner object for the Sentinel Incident
				Switch($json.operator) {
					"**TopDesk Operator Name 1**" { $user = get-azaduser -userprincipalname '**Operator1 UPN**'}
					"**TopDesk Operator Name 2**" { $user = get-azaduser -userprincipalname '**Operator2 UPN**'}
					Default { $user = $null }
				}
				write-output ("TopDesk ticket is owned by {0}" -f $json.operator)
				write-output ("Assigning Sentinel incident to {0}" -f $user.UserPrincipalName)

				# Build the Sentinel Incident Owner object to add to the Sentinel Incident.
				if ($user -ne $null) {
					write-output ("Updating owner for Sentinel incident {0}" -f $json.incidentid)
					$owner = New-Object "Microsoft.Azure.Commands.SecurityInsights.Models.Incidents.PSSentinelIncidentOwner"
					$owner.Email = $user.mail
					$owner.UserPrincipalName = $user.UserPrincipalName
					$owner.ObjectID = $user.Id
					$owner.AssignedTo = $user.DisplayName
					
					# Update the incident object for future comparisions
					$incident.Owner = $owner
					$incidentOwner = $incident.Owner

					# Update the incident
					try {
						Update-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Owner $owner
					} catch {
						start-sleep -Seconds 45
						Update-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Owner $owner
					}
				}
			}
		}

		# Check the status of the TopDesk Incident. If the ticket is not closed, assign the Sentinel Incident.
		#
		if ($incidentStatus -eq "New" -and $json.status -ne "Closed") {
			write-output ("Updating incident status to Active for {0}" -f $json.incidentid)
			try {
				Update-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Status 'Active'
			} catch {
				start-sleep -Seconds 45
				Update-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Status 'Active'
			}
		}
	}

	# If the calling TopDesk Action is "Sentinel - Send Action Data"
	if ($json.process -eq "2") {
		Write-Output "Calling TopDesk Action is: Sentinel - Sentinel - Send Action Data"
		# Check for an action in the JSON output.  The Action field in the JSON should include the recently added actions on the ticket
		#
		if ($json.action -ne "") {
			write-output ("Writing action data to incident: {0}" -f $json.action)
			# If the action starts with a date and time stamp followed by an operator, replace that text with nothing to get only the action text.
			if ($json.action -match '(\d{2}\/\d{2}\/\d{4} \d{2}:\d{2} [AP]M) (\S{1,}, \S{1,}: )') {
				$action = ($json.action).Replace($matches[0],"")
			} else {
				$action = $json.action
			}
			New-AzSentinelIncidentComment -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Message $action
		} else {
			write-output "Action field was blank"
		}
	}

	# If the calling TopDesk Action is "Sentinel - Close Incident"
	if ($json.process -eq "3") {
		Write-Output "Calling TopDesk Action is: Sentinel - Sentinel - Close Incident"
		if ($json.classification -eq "") {
			Write-Output ("No classification provided for incident {0} re-opening ticket" -f $json.incidentid)
			write-output "We have an invalid classification value, we should re-open incident"
			$secret = GetSecret $kvName $kvSecretName

			$guid = ([guid]$json.topdeskuuid).tostring()
			$uri = ("https://{0}/tas/api/incidents/id/{1}" -f $topdeskurl,$guid)
			$jsonBody = @{processingStatus=@{id=$processingStatusID;};
				action="Please select a closure classification under Free Fields";
				actionInvisibleForCaller=$true;
				closed=$false;
				completed=$false;
				closedDate=$null;
				completedDate=$null
			} | ConvertTo-JSON
			$headers = @{
				"Content-Type"="application/json"
				"Authorization"=$secret
				}
			write-output ("Attempting to re-open ticket using URL: {0}" -f $url)
			write-output ("JSON Body to send: {0}" -f $jsonBody)
			
			Invoke-RestMethod -Method PATCH -Uri $uri -Headers $headers -Body $jsonBody
		} else {
			if ($json.status -eq "Closed") {
				write-output ("Status for {0} was set to closed" -f $json.incidentid)
				write-output ("Incident Classification was {0}" -f $json.classification)
				if ($json.classification -in $sentinelclassifications) {
					Switch($json.classification) {
						"True positive - suspicious activity" { $classification = "TruePositive"; $classificationreason = "SuspiciousActivity"; break }
						"Benign Positive - suspicious but expected" { $classification = "BenignPositive"; $classificationreason = "SuspiciousButExpected"; break }
						"False Positive - incorrect alert logic" { $classification = "FalsePositive"; $classificationreason = "IncorrectAlertLogic"; break }
						"False Positive - inaccurate data" { $classification = "FalsePositive"; $classificationreason = "InaccurateData"; break }
						"Undetermined" { $classification = "Undetermined"; $classificationreason = "InaccurateData"; break }
					}
					if ($json.action -ne "") {
						write-output ("Writing action data to incident: {0}" -f $json.action)
						# If the action starts with a date and time stamp followed by an operator, replace that text with nothing to get only the action text.
						if ($json.action -match '(\d{2}\/\d{2}\/\d{4} \d{2}:\d{2} [AP]M) (\S{1,}, \S{1,}: )') {
							$action = ($json.action).Replace($matches[0],"")
						} else {
							$action = $json.action
						}
					} else {
						$action = ""
					}
					try {
						if ($classification -eq "Undetermined") {
							Update-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Status "Closed" -Classification $classification -ClassificationComment $action
						} else {
							Update-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Status "Closed" -Classification $classification -ClassificationReason $classificationreason -ClassificationComment $action
						}
					} catch {
						start-sleep -Seconds 45
						if ($classification -eq "Undetermined") {
							Update-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Status "Closed" -Classification $classification -ClassificationComment $action
						} else {
							Update-AzSentinelIncident -ResourceGroupName $rgname -WorkspaceName $wsname -IncidentId $json.incidentid -Status "Closed" -Classification $classification -ClassificationReason $classificationreason -ClassificationComment $action
						}
					}
				}
			} else {
				Write-Output "Called by Close Incident, but incident not closed..."
				throw "Closure status error"
				Exit -1
			}
		}
	}
} catch {
	write-output "we failed..."
	write-output $_
	throw $_
	Exit -1
}
